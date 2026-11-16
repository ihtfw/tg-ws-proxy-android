package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.Condition
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/**
 * The channels to one CF host and their shared HTTP/2 transport (upstream cf_h2._HttpLane).
 * [lock] guards the state of the lane and of all its channels.
 */
internal class CfH2Lane(
    val host: String,
    val laneId: Int,
    val ctx: ProxyContext,
    val t: CfH2Tuning,
    @Volatile var transport: CfH2Transport,
) {
    val lock = ReentrantLock()
    /** Signalled whenever lane or channel request capacity is released. */
    val capacityCond: Condition = lock.newCondition()

    val channels = LinkedHashSet<CfH2Channel>()
    /** Where request threads run (tests hold them back). */
    @Volatile var executor: java.util.concurrent.Executor = ctx.executor
    @Volatile var failedUntil = 0.0
    @Volatile var closed = false
        private set

    var tcpConnections = 0
    var requests = 0
    var responses = 0
    var errors = 0
    var slowHeaders = 0
    var slowBodies = 0
    var replays = 0
    var maxHeadersSeconds = 0.0
    var maxBodySeconds = 0.0
    var nextWaitLog = 0.0
    var nextSlowLog = 0.0
    var nextCapacityLog = 0.0
    var nextLargeSlowLog = 0.0
    var capacityRotations = 0
    var inflight = 0
    var queuedBytes = 0L
    var maxInflight = 0
    var replyBufferBytes = 0L

    private val laneEvents = object : CfH2Events {
        override fun connectStart() = onConnectStart()
    }

    private fun onConnectStart() {
        val (count, channelCount) = lock.withLock {
            tcpConnections++
            tcpConnections to channels.size
        }
        ctx.stats.h2TcpConnections.incrementAndGet()
        ProxyLog.d { "H2 lane=$laneId TCP_OPEN connection=$count host=$host channels=$channelCount" }
    }

    /** HEAD /api: the domain must speak HTTP/2 and have the endpoint (Telegram answers HEAD with 501). */
    fun preflight(timeoutMillis: Long = 0) {
        val started = CfH2Clock.now()
        transport.newCall("HEAD", null, laneEvents).execute(timeoutMillis).use { response ->
            if (response.protocol != CfH2Tuning.HTTP2) {
                throw CfH2ValueError("CF /api preflight negotiated " + response.protocol)
            }
            val status = response.status
            if (!(status in 200..299 || status == 405 || status == 501)) {
                throw CfH2ConnectionError("CF /api preflight HTTP $status cf_ray=${response.header("cf-ray") ?: "-"}")
            }
            ProxyLog.d {
                fmt("H2 lane=%d ready host=%s status=%d ms=%.0f", laneId, host, status, (CfH2Clock.now() - started) * 1000)
            }
        }
    }

    /** Caller holds [lock]. */
    fun hasCapacity(length: Int): Boolean =
        inflight < t.maxLaneRequests && queuedBytes + length <= t.maxLaneBytes

    /** Caller holds [lock]. False only when not waiting and there is no room. */
    fun reserveLocked(length: Int, wait: Boolean): Boolean {
        if (!wait && !hasCapacity(length)) return false
        if (wait) awaitLocked(capacityCond, t.requestTimeout, "H2 lane capacity") { closed || hasCapacity(length) }
        if (closed) throw CfH2ConnectionError("H2 lane closed")
        inflight++
        queuedBytes += length
        if (inflight > maxInflight) maxInflight = inflight
        return true
    }

    /** Caller holds [lock]. */
    fun releaseLocked(length: Int) {
        inflight--
        queuedBytes -= length
        capacityCond.signalAll()
    }

    /**
     * POSTs one native packet and returns the whole response body (possibly empty).
     * Blocking; [task] identifies the channel's request for cancellation and tracing.
     */
    fun post(
        body: ByteArray,
        channelId: Int,
        replay: Boolean = false,
        channel: CfH2Channel? = null,
        task: CfH2Task? = null,
    ): ByteArray {
        val requestId: Int
        val trace: CfH2Trace?
        lock.withLock {
            requests++
            if (replay) replays++
            requestId = requests
            trace = if (channel != null && task != null) channel.requestTraces[task] else null
            if (trace != null) {
                trace.request = requestId
                trace.phase = "connect-or-slot"
            }
        }
        ctx.stats.h2Requests.incrementAndGet()
        val started = CfH2Clock.now()
        var buffered = 0L
        var receiving = false

        val events = object : CfH2Events {
            override fun connectStart() {
                onConnectStart()
                if (trace != null) lock.withLock { trace.phase = "connect" }
            }

            override fun requestHeadersStart() {
                if (trace != null) lock.withLock { trace.phase = "upload" }
            }

            override fun requestBodyEnd() {
                lock.withLock {
                    val now = CfH2Clock.now()
                    if (channel != null && task != null && task in channel.pending) channel.sentSince[task] = now
                    if (trace != null) {
                        trace.sentAt = now
                        trace.phase = if (trace.headersAt == null) "headers" else "body"
                    }
                }
            }
        }

        try {
            val call = transport.newCall("POST", body, events)
            task?.attach(call)
            call.execute().use { response ->
                val headersAt = CfH2Clock.now()
                val ray = response.header("cf-ray") ?: "-"
                lock.withLock {
                    if (trace != null) trace.cfRay = ray.take(64).filter { it.code < 128 && (it.isLetterOrDigit() || it == '-') }
                    if (headersAt - started >= t.slowResponseSeconds) slowHeaders++
                    if (headersAt - started > maxHeadersSeconds) maxHeadersSeconds = headersAt - started
                }
                if (response.protocol != CfH2Tuning.HTTP2) throw CfH2ValueError("CF /api downgraded to " + response.protocol)
                val status = response.status
                if (status in CfH2Tuning.TRANSPORT_ERROR_STATUSES) {
                    throw CfH2TransportError(-status, "HTTP $status cf_ray=$ray")
                }
                if (status != 200) throw CfH2ConnectionError("CF /api HTTP $status cf_ray=$ray")
                if ((response.header("content-type") ?: "").lowercase().contains("text/html")) {
                    throw CfH2ValueError("CF /api returned HTML instead of MTProto")
                }
                lock.withLock {
                    if (trace != null && trace.headersAt == null) {
                        trace.headersAt = CfH2Clock.now()
                        trace.phase = "body"
                    }
                    if (channel != null && task != null) {
                        channel.receivingTasks.add(task)
                        channel.lastProgress = CfH2Clock.now()
                        receiving = true
                    }
                }
                val lengthHeader = response.header("content-length")
                val declared = lengthHeader?.let {
                    it.trim().toLongOrNull() ?: throw CfH2ValueError("invalid Content-Length: $it")
                }
                if (declared != null && (declared < 0 || declared > t.maxPacket)) {
                    throw CfH2BufferError("H2 response Content-Length exceeds native packet bound")
                }
                val content = ByteArrayOutputStream(declared?.toInt()?.coerceAtLeast(64) ?: 4096)
                val chunk = ByteArray(16 * 1024)
                while (true) {
                    val n = response.body.read(chunk)
                    if (n < 0) break
                    if (n == 0) continue
                    lock.withLock {
                        if (content.size().toLong() + n > t.maxPacket) {
                            throw CfH2BufferError("H2 response exceeds native packet bound")
                        }
                        if (replyBufferBytes + n > t.maxLaneReplyBytes) {
                            throw CfH2ReplyBufferFull("H2 lane response buffers exceeded bound")
                        }
                        replyBufferBytes += n
                        buffered += n
                        if (trace != null) trace.received += n
                        if (channel != null) channel.lastProgress = CfH2Clock.now()
                    }
                    content.write(chunk, 0, n)
                }
                val received = content.size()
                val encoding = response.header("content-encoding") ?: "identity"
                if (declared != null && encoding == "identity" && received.toLong() != declared) {
                    throw CfH2ValueError("incomplete H2 response body")
                }
                val reply = content.toByteArray()
                if (reply.isNotEmpty() && reply.size % 4 != 0) {
                    throw CfH2ValueError("CF /api response is not an aligned MTProto packet")
                }
                if (reply.size == 4) {
                    val code = Bytes.u32le(reply, 0).toInt()
                    if (code < 0) throw CfH2TransportError(code, "HTTP 200 payload")
                }
                val finished = CfH2Clock.now()
                val bodySeconds = finished - headersAt
                lock.withLock {
                    responses++
                    if (channel != null) {
                        channel.httpBytes += received
                        if (received <= 4096) channel.smallResponses++ else channel.largeResponses++
                    }
                    if (bodySeconds > maxBodySeconds) maxBodySeconds = bodySeconds
                    if (bodySeconds >= t.slowResponseSeconds) slowBodies++
                    val large = received > 4096
                    val nextSlow = if (large) nextLargeSlowLog else nextSlowLog
                    if (finished - started >= t.slowResponseSeconds && finished >= nextSlow) {
                        if (large) nextLargeSlowLog = finished + t.diagnosticInterval
                        else nextSlowLog = finished + t.diagnosticInterval
                        ProxyLog.d {
                            fmt(
                                "H2 SLOW lane=%d channel=%d request=%d bytes=%d replay=%d " +
                                    "headers_ms=%.0f body_ms=%.0f detail=[%s]",
                                laneId, channelId, requestId, received, if (replay) 1 else 0,
                                (headersAt - started) * 1000, bodySeconds * 1000,
                                trace?.summary(finished) ?: "-",
                            )
                        }
                    }
                }
                return reply
            }
        } catch (e: Exception) {
            if (task != null && task.cancelled) throw CfH2Cancelled(e)
            when (e) {
                is CfH2TransportError -> lock.withLock { errors++ }
                is CfH2ReplyBufferFull -> {}
                is IOException -> lock.withLock {
                    errors++
                    failedUntil = CfH2Clock.now() + t.domainCooldown
                }
            }
            throw e
        } finally {
            lock.withLock {
                replyBufferBytes -= buffered
                if (receiving && channel != null) channel.receivingTasks.remove(task)
            }
        }
    }

    /** The H2 WAIT/DETAIL debug lines for channels whose requests have waited long. */
    fun logWait(now: Double) {
        if (!ProxyLog.verbose) return
        lock.withLock {
            if (now < nextWaitLog) return
            nextWaitLog = now + 1.0
            val slow = t.slowResponseSeconds
            val waiting = channels.filter { ch ->
                val delivering = ch.deliveringSince?.let { now - it >= slow } == true
                val stalled = ch.pendingSince.any { (task, since) ->
                    task !in ch.replayPending && task !in ch.receivingTasks && now - since >= slow
                }
                (delivering || stalled) && now - ch.lastNativeSend <= t.replayMaxAge
            }.sortedBy { it.channelId }
            if (waiting.isEmpty()) return
            nextWaitLog = now + t.diagnosticInterval
            ProxyLog.d(
                fmt(
                    "H2 WAIT lane=%d affected=%d inflight=%d body_buffer=%d [%s]",
                    laneId, waiting.size, inflight, replyBufferBytes,
                    waiting.take(8).joinToString("; ") { it.waitState(now) },
                )
            )
            val details = waiting.flatMap { ch ->
                ch.requestTraces.values.filter { !it.replay && now - it.started >= slow }.map { ch to it }
            }.sortedBy { it.second.started }.take(12)
            if (details.isNotEmpty()) {
                ProxyLog.d(
                    fmt(
                        "H2 DETAIL lane=%d [%s]", laneId,
                        details.joinToString("; ") { (ch, trace) -> ch.requestDetail(trace, now) },
                    )
                )
            }
        }
    }

    fun logFlow(now: Double) {
        if (!ProxyLog.verbose) return
        lock.withLock {
            if (channels.isEmpty()) return
            val sorted = channels.sortedBy { it.channelId }
            for (part in sorted.chunked(8)) {
                ProxyLog.d(fmt("H2 FLOW lane=%d [%s]", laneId, part.joinToString("; ") { it.flowState(now) }))
            }
        }
    }

    fun summary(): String = lock.withLock {
        fmt(
            "lane=%d host=%s channels=%d tcp_connections=%d requests=%d replies=%d " +
                "errors=%d inflight=%d max_inflight=%d queued_bytes=%d reply_buffer_bytes=%d " +
                "replays=%d capacity_rotations=%d slow_headers=%d slow_bodies=%d max_headers_ms=%.0f max_body_ms=%.0f",
            laneId, host, channels.size, tcpConnections, requests, responses, errors, inflight,
            maxInflight, queuedBytes, replyBufferBytes, replays, capacityRotations, slowHeaders, slowBodies,
            maxHeadersSeconds * 1000, maxBodySeconds * 1000,
        )
    }

    fun close() {
        closed = true
        val all = lock.withLock {
            capacityCond.signalAll()
            channels.toList()
        }
        for (channel in all) channel.close()
        transport.closeQuietly()
        ProxyLog.d { "H2 CLOSED " + summary() }
    }
}

/**
 * Waits on [cond] (whose lock the caller holds) until [ready], at most [timeoutSeconds];
 * throws [CfH2Timeout] after that (upstream: asyncio.wait_for(condition.wait_for(...))).
 */
internal inline fun awaitLocked(cond: Condition, timeoutSeconds: Double, what: String, ready: () -> Boolean) {
    var left = (timeoutSeconds * 1e9).toLong()
    while (!ready()) {
        if (left <= 0) throw CfH2Timeout("$what wait timed out")
        left = cond.awaitNanos(left)
    }
}

/** Waits for [ms] milliseconds, giving up early when interrupted. */
internal fun CfH2Task.awaitDoneQuietly(ms: Long): Boolean = try {
    awaitDone(ms, TimeUnit.MILLISECONDS)
} catch (_: InterruptedException) {
    Thread.currentThread().interrupt()
    false
}
