package org.flowseal.tgwsproxy.proxy

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.math.max

/** One HTTP request of a channel, run on its own thread (upstream: the asyncio.Task of _run_request). */
internal class CfH2Task {
    @Volatile var cancelled = false
        private set
    @Volatile var done = false
        private set
    private var call: CfH2Call? = null
    private val finished = CountDownLatch(1)

    fun attach(c: CfH2Call) {
        val cancelNow = synchronized(this) {
            call = c
            cancelled
        }
        if (cancelNow) c.cancel()
    }

    fun cancel() {
        val c = synchronized(this) {
            cancelled = true
            call
        }
        c?.cancel()
    }

    fun markDone() {
        done = true
        finished.countDown()
    }

    fun awaitDone(timeout: Long, unit: TimeUnit): Boolean = finished.await(timeout, unit)
}

/** A packet the client sent recently, kept to be re-sent (upstream _ReplayPacket). */
internal class CfH2ReplayPacket(var sentAt: Double, val body: ByteArray, val sequence: Int) {
    var attempts = 0
    var lastAttemptAt = 0.0
    var pending: CfH2Task? = null
    val originals = LinkedHashSet<CfH2Task>()
    var retired = false
    var replyId: ByteArray? = null

    val replayed: Boolean get() = lastAttemptAt > 0 || attempts > 0
}

/** Debug timing of one request (upstream _RequestTrace); only kept when ProxyLog.verbose. */
internal class CfH2Trace(val packet: Int, var started: Double, val replay: Boolean, val size: Int) {
    var request = 0
    var phase = "queued"
    var sentAt: Double? = null
    var headersAt: Double? = null
    var finishedAt: Double? = null
    var received = 0L
    var cfRay = "-"

    fun summary(now: Double): String {
        val end = finishedAt ?: now
        val headers = headersAt ?: end
        val sent = sentAt
        val sendMs = if (sent == null) -1.0 else (sent - started) * 1000
        val headersMs = if (sent == null) -1.0 else max(0.0, headers - sent) * 1000
        return fmt(
            "req=%d pkt=%d replay=%d phase=%s age_ms=%.0f send_ms=%.0f wait_headers_ms=%.0f up=%d down=%d ray=%s",
            request, packet, if (replay) 1 else 0, phase, (end - started) * 1000, sendMs, headersMs,
            size, received, cfRay,
        )
    }
}

/**
 * One client connection carried as HTTP requests on a lane (upstream cf_h2._HttpChannel).
 * Its state is guarded by the lane's lock; obtain one from [CfH2Pool.open] and pass it to [bridgeH2].
 */
class CfH2Channel internal constructor(
    internal val lane: CfH2Lane,
    internal val channelId: Int,
    internal val label: String,
) {
    private val t = lane.t
    private val lock = lane.lock

    @Volatile internal var closed = false
        private set
    @Volatile internal var transportError: Int? = null
        private set

    internal val pending = LinkedHashMap<CfH2Task, Int>()
    internal val pendingSince = HashMap<CfH2Task, Double>()
    internal val sentSince = LinkedHashMap<CfH2Task, Double>()
    internal var pendingBytes = 0L
    internal var replyBytes = 0L
    /** Replies (ByteArray) and, last, the error that ended the channel (Throwable). */
    internal val queue = ArrayDeque<Any>()
    private val queueCond = lock.newCondition()
    private val recoveryCond = lock.newCondition()
    private var recoveryWake = false
    private var recoveryStopped = false

    internal var requests = 0
    internal var up = 0L
    internal var down = 0L
    internal var quickRequests = 0
    internal val started = CfH2Clock.now()
    internal val receivingTasks = HashSet<CfH2Task>()
    internal var deliveringSince: Double? = null
    internal val replayPending = HashSet<CfH2Task>()
    internal val replayHistory = ArrayList<CfH2ReplayPacket>()
    private var replayKey: ByteArray? = null
    internal var replayRequests = 0
    internal var pollRequests = 0
    private var firstPollGap = 0.0
    internal var replayRotations = 0
    internal var capacityRotations = 0
    internal var lastProgress = started
    internal var lastNativeSend = started
    private val closeLock = ReentrantLock()
    internal val sendLock = ReentrantLock()
    @Volatile internal var closeDone = false
        private set
    internal val requestTraces = LinkedHashMap<CfH2Task, CfH2Trace>()
    internal val recentTraces = ArrayDeque<CfH2Trace>()
    internal var uploadWaitSince: Double? = null
    internal var uploadWaitPhase = "-"
    internal var uploadWaitBytes = 0
    internal var httpBytes = 0L
    internal var smallResponses = 0
    internal var largeResponses = 0
    private var flowSample = doubleArrayOf(started, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)

    init {
        lock.withLock { lane.channels.add(this) }
    }

    internal val receivingHttp: Int get() = lock.withLock { receivingTasks.size }

    /** Caller holds the lock. */
    internal val nativeBackpressure: Boolean get() = replyBytes != 0L || deliveringSince != null

    /** Caller holds the lock. */
    internal fun hasCapacity(length: Int): Boolean =
        pending.size < t.maxChannelRequests && pendingBytes + length <= t.maxChannelBytes

    /** Caller holds the lock. */
    internal fun wakeReceiver() {
        if (!closed && pending.isEmpty() && !nativeBackpressure) {
            recoveryWake = true
            recoveryCond.signalAll()
        }
    }

    private fun overdueOriginal(entry: CfH2ReplayPacket, now: Double): Boolean =
        entry.retired || entry.originals.any { task ->
            val sent = sentSince[task]
            sent != null && task !in receivingTasks && now - sent >= t.replayRequestSeconds
        }

    private fun replayLimit(entry: CfH2ReplayPacket): Int =
        if (entry.originals.isNotEmpty() || entry.retired || entry === replayHistory.lastOrNull()) {
            t.replayMaxAttempts
        } else {
            0
        }

    /** The request to cancel so that a waiting upload gets room, and its packet if it was an original. */
    private fun capacityCandidate(now: Double): Pair<CfH2Task, CfH2ReplayPacket?>? {
        val ordered = sentSince.entries.sortedWith(compareBy({ it.key !in replayPending }, { it.value }))
        for ((task, sent) in ordered) {
            if (task.done || task in receivingTasks || now - sent < t.replayRequestSeconds) continue
            if (task in replayPending) return task to null
            val entry = replayHistory.firstOrNull { task in it.originals }
            if (entry != null && now - entry.sentAt <= t.replayMaxAge) return task to entry
        }
        return null
    }

    /**
     * When the client's next packet waits for channel or lane capacity, cancels one long poll
     * that has had its full chance (upstream _make_upload_room). Its packet stays replayable.
     */
    internal fun makeUploadRoom(now: Double) {
        var victim: CfH2Task? = null
        var victimChannel: CfH2Channel? = null
        lock.withLock {
            if (closed || uploadWaitSince == null) return
            val candidates: List<CfH2Channel> = when (uploadWaitPhase) {
                "channel-capacity" -> if (hasCapacity(uploadWaitBytes)) return else listOf(this)
                "lane-capacity" -> if (lane.hasCapacity(uploadWaitBytes)) return else {
                    lane.channels.sortedBy { ch -> ch.sentSince.values.minOrNull() ?: now }
                }
                else -> return
            }
            for (channel in candidates) {
                val (task, entry) = channel.capacityCandidate(now) ?: continue
                channel.sentSince.remove(task)
                if (entry != null) entry.retired = true
                channel.requestTraces[task]?.let { it.phase = "capacity-" + it.phase }
                if (now >= lane.nextCapacityLog) {
                    lane.nextCapacityLog = now + t.diagnosticInterval
                    ProxyLog.d {
                        fmt(
                            "H2 CAPACITY lane=%d waiting_channel=%d release_channel=%d reason=%s replay=%d " +
                                "wait_ms=%.0f inflight=%d",
                            lane.laneId, channelId, channel.channelId, uploadWaitPhase,
                            if (task in channel.replayPending) 1 else 0,
                            (now - (uploadWaitSince ?: now)) * 1000, lane.inflight,
                        )
                    }
                }
                victim = task
                victimChannel = channel
                break
            }
        }
        val task = victim ?: return
        task.cancel()
        task.awaitDoneQuietly(t.cancelWaitMillis)
        lock.withLock {
            victimChannel!!.capacityRotations++
            lane.capacityRotations++
        }
    }

    /** Why [entry] is not re-sent now, or null when it is due (upstream _replay_blocker). */
    internal fun replayBlocker(entry: CfH2ReplayPacket, now: Double): String? {
        val age = now - entry.sentAt
        if (age < 0 || age > t.replayMaxAge) return "expired"
        if (entry.attempts >= replayLimit(entry)) return "budget-used"
        if (nativeBackpressure) return "native-backpressure"
        if (entry.originals.any { it in receivingTasks }) return "original-body"
        if (entry.pending?.let { it in receivingTasks } == true) return "replay-body"
        if (entry.replayed && now - entry.lastAttemptAt < t.replayRetrySeconds) return "backoff-or-progress"
        if (overdueOriginal(entry, now)) return null
        if (entry !== replayHistory.lastOrNull() || pending.keys.any { it !== entry.pending }) return "receiver-active"
        if (entry.replayed && now - lastProgress < t.replayIdleSeconds) return "backoff-or-progress"
        return null
    }

    private fun replayDue(entry: CfH2ReplayPacket, now: Double): Boolean = replayBlocker(entry, now) == null

    /** Caller holds the lock. */
    internal fun waitState(now: Double): String {
        val oldest = pendingSince.values.minOrNull() ?: now
        val recoveryLeft = replayHistory.filter { now - it.sentAt <= t.replayMaxAge }
            .sumOf { max(0, replayLimit(it) - it.attempts) }
        val waitingHeaders = pendingSince.count { (task, since) ->
            task !in replayPending && task !in receivingTasks && now - since >= t.replayRequestSeconds
        }
        return fmt(
            "channel=%d pending=%d replays=%d receiving=%d ready_bytes=%d native_write=%d idle_ms=%.0f " +
                "oldest_ms=%.0f native_age_ms=%.0f recovery_left=%d waiting_headers=%d",
            channelId, pending.size, replayPending.size, receivingTasks.size, replyBytes,
            if (deliveringSince != null) 1 else 0, (now - lastProgress) * 1000, (now - oldest) * 1000,
            (now - lastNativeSend) * 1000, recoveryLeft, waitingHeaders,
        )
    }

    /** Caller holds the lock. */
    internal fun requestDetail(trace: CfH2Trace, now: Double): String {
        val entry = replayHistory.firstOrNull { it.sequence == trace.packet }
        var recovery = "not-retained"
        var attempts = "-"
        if (entry != null) {
            attempts = "${entry.attempts}/${replayLimit(entry)}"
            val entryPending = entry.pending
            recovery = replayBlocker(entry, now) ?: when {
                entryPending != null -> if (entryPending in receivingTasks) "replay-body" else
                    fmt("probe-%.0fms", (now - (pendingSince[entryPending] ?: now)) * 1000)
                replayPending.size >= t.maxChannelReplays -> "replay-slots"
                !hasCapacity(entry.body.size) -> "channel-capacity"
                !lane.hasCapacity(entry.body.size) -> "lane-capacity"
                sendLock.isLocked -> "send-lock"
                else -> "eligible"
            }
        }
        val related = recentTraces.filter { it.packet == trace.packet }.takeLast(2)
        return "channel=$channelId ${trace.summary(now)} attempts=$attempts recovery=$recovery " +
            "recent=[${related.joinToString("; ") { it.summary(now) }}]"
    }

    /** Caller holds the lock. Counters since the previous call (upstream _flow_state). */
    internal fun flowState(now: Double): String {
        val previous = flowSample
        val current = doubleArrayOf(
            now, requests.toDouble(), replayRequests.toDouble(), httpBytes.toDouble(), down.toDouble(),
            smallResponses.toDouble(), largeResponses.toDouble(), pollRequests.toDouble(),
        )
        flowSample = current
        val pollGap = firstPollGap
        firstPollGap = 0.0
        val probes = requestTraces.values.filter { it.replay }.take(2).joinToString("; ") { it.summary(now) }
        val d = LongArray(8) { (current[it] - previous[it]).toLong() }
        return fmt(
            "channel=%d window_ms=%.0f requests=%d replays=%d http_down=%d native_down=%d small=%d large=%d " +
                "pending=%d ready=%d upload_wait=%s/%.0fms native_write_ms=%.0f capacity_rotations=%d " +
                "polls=%d first_poll_ms=%.0f probes=[%s]",
            channelId, (now - previous[0]) * 1000, d[1], d[2], d[3], d[4], d[5], d[6],
            pending.size, replyBytes, uploadWaitPhase, uploadWaitSince?.let { (now - it) * 1000 } ?: 0.0,
            deliveringSince?.let { (now - it) * 1000 } ?: 0.0, capacityRotations, d[7], pollGap * 1000, probes,
        )
    }

    /** Ends the channel with [error], which [receive] then throws (upstream _fail). */
    internal fun fail(error: Throwable) {
        lock.withLock {
            if (closed) return
            if (error is CfH2TransportError) transportError = error.code
            closed = true
            recoveryWake = true
            recoveryCond.signalAll()
            queue.clear()
            replyBytes = 0
            queue.addLast(error)
            queueCond.signalAll()
            lane.capacityCond.signalAll()
        }
    }

    /**
     * Sends one native packet as a POST without waiting for its answer. A native packet waits for
     * channel and lane capacity; a [replay] returns false instead of waiting.
     */
    internal fun send(body: ByteArray, quick: Boolean, replay: Boolean = false): Boolean {
        if (replay) {
            if (!sendLock.tryLock()) return false
            try {
                return sendLocked(body, quick, true)
            } finally {
                sendLock.unlock()
            }
        }
        lock.withLock {
            uploadWaitSince = CfH2Clock.now()
            uploadWaitPhase = "send-lock"
            uploadWaitBytes = body.size
        }
        try {
            sendLock.lockInterruptibly()
            try {
                return sendLocked(body, quick, false)
            } finally {
                sendLock.unlock()
            }
        } finally {
            lock.withLock {
                uploadWaitSince = null
                uploadWaitPhase = "-"
                uploadWaitBytes = 0
            }
        }
    }

    private fun sendLocked(body: ByteArray, quick: Boolean, replay: Boolean): Boolean = lock.withLock {
        val length = body.size
        if (replay && !hasCapacity(length)) return false
        if (!replay) {
            uploadWaitPhase = "channel-capacity"
            awaitLocked(lane.capacityCond, t.requestTimeout, "H2 channel capacity") { closed || hasCapacity(length) }
        }
        if (closed) throw CfH2ConnectionError("H2 channel closed")
        if (!replay) uploadWaitPhase = "lane-capacity"
        if (!lane.reserveLocked(length, wait = !replay)) return false
        if (closed) {
            lane.releaseLocked(length)
            throw CfH2ConnectionError("H2 channel closed")
        }
        val replayPacket = if (replay) findPacket(body) else null
        val now = CfH2Clock.now()
        if (replay && (replayPacket == null || replayPacket.pending != null || !replayDue(replayPacket, now))) {
            lane.releaseLocked(length)
            return false
        }
        pendingBytes += length
        requests++
        if (replay) replayRequests++
        up += length
        lane.ctx.stats.bytesUp.addAndGet(length.toLong())
        if (!replay) lastNativeSend = now
        val nativePacket = if (!replay) rememberPacket(body, now) else null
        if (quick) quickRequests++
        val packet = replayPacket ?: nativePacket
        val trace = if (ProxyLog.verbose) CfH2Trace(packet?.sequence ?: requests, now, replay, length) else null
        val task = CfH2Task()
        pending[task] = length
        pendingSince[task] = now
        if (trace != null) requestTraces[task] = trace
        if (nativePacket != null) {
            nativePacket.originals.add(task)
            trimHistory(now)
        }
        if (replayPacket != null) {
            if (!overdueOriginal(replayPacket, now)) {
                pollRequests++
                if (!replayPacket.replayed) firstPollGap = max(firstPollGap, now - lastProgress)
            }
            replayPending.add(task)
            replayPacket.attempts++
            replayPacket.lastAttemptAt = now
            replayPacket.pending = task
        }
        try {
            lane.executor.execute { runRequest(task, body, replay, packet, trace) }
        } catch (e: RejectedExecutionException) {
            finishRequest(task, packet)
            task.markDone()
            throw CfH2ConnectionError("H2 request not started: proxy stopping")
        }
        true
    }

    private fun findPacket(body: ByteArray): CfH2ReplayPacket? = replayHistory.firstOrNull { it.body.contentEquals(body) }

    private fun rememberPacket(body: ByteArray, now: Double): CfH2ReplayPacket? {
        // Plaintext packets (auth key negotiation) are never re-sent.
        if (CfH2Framing.isZero8(body)) return null
        val key = body.copyOf(minOf(8, body.size))
        if (!key.contentEquals(replayKey)) {
            replayHistory.clear()
            replayKey = key
        }
        if (body.size > t.replayHistoryBytes) return null
        return findPacket(body) ?: CfH2ReplayPacket(now, body, requests).also { replayHistory.add(it) }
    }

    private fun trimHistory(now: Double) {
        var retained = replayHistory.sumOf { it.body.size }
        while (replayHistory.size > t.replayHistoryPackets || retained > t.replayHistoryBytes) {
            val victim = replayHistory.firstOrNull { entry ->
                entry.originals.isEmpty() && !(entry.retired && entry.attempts < t.replayMaxAttempts &&
                    now - entry.sentAt <= t.replayMaxAge)
            } ?: replayHistory[0]
            replayHistory.remove(victim)
            retained -= victim.body.size
        }
    }

    private fun runRequest(task: CfH2Task, body: ByteArray, replay: Boolean, packet: CfH2ReplayPacket?, trace: CfH2Trace?) {
        try {
            if (task.cancelled) throw CfH2Cancelled()
            val reply = lane.post(body, channelId, replay, this, task)
            lock.withLock {
                lastProgress = CfH2Clock.now()
                if (reply.isNotEmpty() && !closed) {
                    if (packet != null) {
                        val id = reply.copyOf(minOf(24, reply.size))
                        if (!id.contentEquals(packet.replyId)) {
                            // A new answer: the packet still solicits replies, so polling may go on.
                            packet.replyId = id
                            packet.attempts = 0
                        }
                    }
                    if (queue.size >= CfH2Tuning.QUEUE_SIZE || replyBytes + reply.size > t.maxChannelBytes) {
                        throw CfH2BufferError("H2 client response queue exceeded bound")
                    }
                    replyBytes += reply.size
                    queue.addLast(reply)
                    queueCond.signalAll()
                }
                if (trace != null) trace.phase = "complete"
            }
        } catch (_: CfH2Cancelled) {
            if (trace != null) lock.withLock { trace.phase = "cancelled-" + trace.phase }
        } catch (e: CfH2TransportError) {
            if (trace != null) lock.withLock { trace.phase = "transport-error" }
            lane.ctx.stats.h2Errors.incrementAndGet()
            if (!closed) {
                ProxyLog.w(
                    "[$label] H2 lane=${lane.laneId} channel=$channelId host=${lane.host} MTProto transport " +
                        "error=${e.message} request=${trace?.request ?: 0} encrypted=${if (CfH2Framing.isZero8(body)) 0 else 1} " +
                        "bytes=${body.size} replay=${if (replay) 1 else 0}; reporting to client"
                )
            }
            fail(e)
        } catch (e: Exception) {
            val detail = lock.withLock {
                if (trace != null) trace.phase = "error-" + errName(e)
                trace?.summary(CfH2Clock.now()) ?: "-"
            }
            lane.ctx.stats.h2Errors.incrementAndGet()
            if (e is IOException) {
                ProxyLog.w(
                    "[$label] H2 lane=${lane.laneId} channel=$channelId request failed: ${errName(e)}: ${e.message}; " +
                        "detail=[$detail]; closing native channel, reconnect may select another domain"
                )
            } else {
                ProxyLog.e("[$label] H2 lane=${lane.laneId} channel=$channelId unexpected request failure: $e")
            }
            fail(e)
        } finally {
            finishRequest(task, packet)
            task.markDone()
        }
    }

    internal fun finishRequest(task: CfH2Task, packetHint: CfH2ReplayPacket? = null) {
        lock.withLock {
            val length = pending.remove(task) ?: return
            requestTraces.remove(task)?.let { trace ->
                trace.finishedAt = CfH2Clock.now()
                recentTraces.addLast(trace)
                while (recentTraces.size > RECENT_TRACES) recentTraces.removeFirst()
            }
            pendingBytes -= length
            pendingSince.remove(task)
            sentSince.remove(task)
            replayPending.remove(task)
            val packet = packetHint ?: replayHistory.firstOrNull { task in it.originals || it.pending === task }
            if (packet != null) {
                packet.originals.remove(task)
                if (packet.pending === task) packet.pending = null
            }
            lane.releaseLocked(length)
            wakeReceiver()
        }
    }

    /**
     * Re-sends kept packets while the channel lives (upstream _recover): when every request has
     * been answered and the client waits for more, or when an original went unanswered too long.
     * Returns once the channel closes or [stopRecovery] is called.
     */
    internal fun recover() {
        while (true) {
            lock.withLock {
                if (closed || recoveryStopped) return
                if (!recoveryWake) recoveryCond.awaitNanos((t.replayCheckSeconds * 1e9).toLong())
                recoveryWake = false
                if (closed || recoveryStopped) return
            }
            val now = CfH2Clock.now()
            lane.logWait(now)
            makeUploadRoom(now)
            val (entry, replace) = pickReplay(now) ?: continue
            if (replace != null) {
                replace.cancel()
                replace.awaitDoneQuietly(t.cancelWaitMillis)
                lock.withLock { replayRotations++ }
            }
            send(entry.body, false, replay = true)
        }
    }

    /** The packet to re-send now and the replay request it takes the slot of, if any. */
    private fun pickReplay(now: Double): Pair<CfH2ReplayPacket, CfH2Task?>? = lock.withLock {
        if (closed || nativeBackpressure) return null
        val overdue = replayHistory.associateWith { overdueOriginal(it, now) }
        val candidates = replayHistory.sortedWith(
            compareBy({ !overdue.getValue(it) }, { if (overdue.getValue(it)) it.sequence else -it.sequence })
        )
        for (entry in candidates) {
            if (!replayDue(entry, now)) continue
            var replace = entry.pending
            if (replace == null && replayPending.size >= t.maxChannelReplays) {
                replace = pending.keys.firstOrNull { it in replayPending && it !in receivingTasks } ?: continue
            }
            if (replace != null) {
                val sent = sentSince[replace]
                if (replace in receivingTasks || sent == null || now - sent < t.replaySlotSeconds) continue
            }
            return entry to replace
        }
        null
    }

    internal fun stopRecovery() {
        lock.withLock {
            recoveryStopped = true
            recoveryCond.signalAll()
        }
    }

    /**
     * The next reply for the client, blocking; throws the error that ended the channel.
     * [timeoutMillis] >= 0 bounds the wait (java.util.concurrent.TimeoutException), for tests.
     */
    internal fun receive(timeoutMillis: Long = -1): ByteArray = lock.withLock {
        var left = if (timeoutMillis >= 0) TimeUnit.MILLISECONDS.toNanos(timeoutMillis) else Long.MAX_VALUE
        while (queue.isEmpty()) {
            if (timeoutMillis < 0) {
                queueCond.await()
            } else {
                if (left <= 0) throw java.util.concurrent.TimeoutException("no H2 reply in ${timeoutMillis}ms")
                left = queueCond.awaitNanos(left)
            }
        }
        val value = queue.first()
        if (value is Throwable) throw value
        queue.removeFirst()
        val reply = value as ByteArray
        replyBytes -= reply.size
        wakeReceiver()
        reply
    }

    /** Cancels every request of the channel and leaves the lane; idempotent. */
    internal fun close() {
        closeLock.withLock {
            if (closeDone) return
            val waiting = lock.withLock {
                val now = CfH2Clock.now()
                if (ProxyLog.verbose && requestTraces.isNotEmpty()) {
                    val traces = requestTraces.values.sortedBy { it.started }.take(3)
                    ProxyLog.d(
                        "H2 DETAIL CLOSE lane=${lane.laneId} [" +
                            traces.joinToString("; ") { requestDetail(it, now) } + "]"
                    )
                }
                waitState(now)
            }
            fail(CfH2ConnectionError("H2 channel closed"))
            val tasks = lock.withLock {
                closed = true
                pending.keys.toList()
            }
            for (task in tasks) task.cancel()
            for (task in tasks) task.awaitDoneQuietly(t.cancelWaitMillis)
            lock.withLock {
                for (task in pending.keys.toList()) finishRequest(task)
                replayPending.clear()
                replayHistory.clear()
                sentSince.clear()
                requestTraces.clear()
                recentTraces.clear()
                lane.channels.remove(this)
                closeDone = true
                ProxyLog.d {
                    fmt(
                        "[%s] H2 channel=%d closed lane=%d requests=%d replays=%d rotations=%d capacity_rotations=%d " +
                            "up=%d down=%d quickack=%d duration=%.1fs remaining_channels=%d; %s",
                        label, channelId, lane.laneId, requests, replayRequests, replayRotations, capacityRotations,
                        up, down, quickRequests, CfH2Clock.now() - started, lane.channels.size, waiting,
                    )
                }
            }
        }
    }

    private companion object {
        const val RECENT_TRACES = 16
    }
}
