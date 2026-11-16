package org.flowseal.tgwsproxy.proxy

import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.util.Locale
import java.util.concurrent.Future
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/*
 * Telegram media connections through the Cloudflare proxy as HTTP/2 POSTs to
 * https://kws<dc>.<cf-domain>/api (upstream proxy/cf_h2.py and proxy/h2_transport.py).
 *
 * Every native MTProto packet from the client becomes one POST; every non-empty response body
 * becomes one packet back. Media channels to one host share a lane (one HTTP/2 connection).
 * Telegram's HTTP transport answers a request only when it has something to say, so a channel
 * keeps the client's recent packets and re-sends one ("replay"/"poll") when no request is left
 * to carry the server's next reply, or when an original request got no answer in time.
 */

/** Limits and timings (upstream cf_h2.py module constants); tests shrink them. */
internal data class CfH2Tuning(
    var maxPacket: Int = MAX_PACKET,
    var maxPlainPadding: Int = MAX_PLAIN_PADDING,
    var maxChannelRequests: Int = 8,
    var maxChannelBytes: Long = 8L * 1024 * 1024,
    var maxLaneRequests: Int = 64,
    var maxLaneBytes: Long = 32L * 1024 * 1024,
    var maxLaneReplyBytes: Long = 32L * 1024 * 1024,
    var domainCooldown: Double = 30.0,
    var requestTimeout: Double = REQUEST_TIMEOUT_SECONDS.toDouble(),
    var setupTimeout: Double = 8.0,
    var replayIdleSeconds: Double = 1.0,
    var replayRequestSeconds: Double = 3.0,
    var replayCheckSeconds: Double = 0.25,
    var replayMaxAge: Double = 30.0,
    var replayHistoryBytes: Int = 64 * 1024,
    var replayHistoryPackets: Int = 16,
    var maxChannelReplays: Int = 2,
    var replaySlotSeconds: Double = 30.0,
    var replayRetrySeconds: Double = 2.0,
    var replayMaxAttempts: Int = 3,
    var slowResponseSeconds: Double = 3.0,
    var diagnosticInterval: Double = 5.0,
    /** How long close and rotations wait for a cancelled request's thread to finish. */
    var cancelWaitMillis: Long = 5000,
) {
    companion object {
        const val MAX_PACKET = 4 * 1024 * 1024
        const val MAX_PLAIN_PADDING = 256
        const val REQUEST_TIMEOUT_SECONDS = 65L
        const val QUEUE_SIZE = 16
        const val HTTP2 = "HTTP/2"
        /** Statuses the client must see as an MTProto transport error (-status), not as EOF. */
        val TRANSPORT_ERROR_STATUSES = setOf(403, 404, 429, 444)
    }
}

/** Upstream ValueError: a malformed packet or response. */
internal open class CfH2ValueError(message: String) : IOException(message)

/** Upstream BufferError: a size bound was exceeded. */
internal open class CfH2BufferError(message: String) : IOException(message)

/** A local memory limit (upstream _ReplyBufferFull): does not cool the domain down. */
internal class CfH2ReplyBufferFull(message: String) : CfH2BufferError(message)

/** Upstream ConnectionError: the endpoint, a channel or a lane is unusable. */
internal class CfH2ConnectionError(message: String) : IOException(message)

/** An endpoint error that the native client must receive as code [code], not just EOF. */
internal class CfH2TransportError(val code: Int, source: String) : IOException("$code ($source)")

/** The local client disconnected (upstream _NativeDeliveryError). */
internal class CfH2NativeDeliveryError(message: String?) : IOException(message)

/** Waiting for request capacity took too long (upstream asyncio.TimeoutError). */
internal class CfH2Timeout(message: String) : IOException(message)

/** A request cancelled by recovery, capacity rotation or close (upstream asyncio.CancelledError). */
internal class CfH2Cancelled(cause: Throwable? = null) : IOException("H2 request cancelled", cause)

internal object CfH2Clock {
    private val origin = System.nanoTime()

    /** Seconds on a monotonic clock that starts well above zero, like Python's time.monotonic(). */
    fun now(): Double = 1e6 + (System.nanoTime() - origin) / 1e9
}

internal fun fmt(format: String, vararg args: Any?): String = String.format(Locale.US, format, *args)

internal fun errName(e: Throwable): String = e.javaClass.simpleName

/**
 * HTTP/2 lanes to the Cloudflare proxy for media connections (upstream cf_h2.CfH2Pool).
 * Thread-safe; [open] blocks for at most the setup timeout (8 s).
 */
class CfH2Pool internal constructor(
    private val ctx: ProxyContext,
    internal val tuning: CfH2Tuning,
    private val transportFactory: (host: String) -> CfH2Transport,
) : AutoCloseable {

    constructor(ctx: ProxyContext) : this(ctx, CfH2Tuning(), { host -> OkHttpCfH2Transport(host) })

    internal var balancer: Balancer = ctx.balancer

    private val state = Any()
    internal val lanes = LinkedHashMap<String, CfH2Lane>()
    private val hostLocks = HashMap<String, ReentrantLock>()
    private val failedUntil = HashMap<String, Double>()
    private val setupRetryAfter = HashMap<Int, Double>()
    private var nextLane = 0
    private var nextChannel = 0

    @Volatile internal var closed = false
        private set

    private class SetupTimeout : Exception()

    /**
     * A channel to the CF proxy for [dc], or null when no domain answered (the caller then tries
     * a WebSocket). Throws IOException once the pool is closed.
     */
    @Throws(IOException::class)
    fun open(dc: Int, label: String): CfH2Channel? {
        if (closed) throw CfH2ConnectionError("H2 pool closed")
        synchronized(state) {
            if (CfH2Clock.now() < (setupRetryAfter[dc] ?: 0.0)) return null
        }
        val deadline = CfH2Clock.now() + tuning.setupTimeout
        return try {
            openBefore(dc, label, deadline)
        } catch (_: SetupTimeout) {
            synchronized(state) { setupRetryAfter[dc] = CfH2Clock.now() + tuning.domainCooldown }
            ctx.stats.h2Errors.incrementAndGet()
            ProxyLog.w(fmt("[%s] H2 DC%d setup timed out; using WS for %.0fs", label, dc, tuning.domainCooldown))
            null
        }
    }

    private fun openBefore(dc: Int, label: String, deadline: Double): CfH2Channel? {
        if (closed) throw CfH2ConnectionError("H2 pool closed")
        if (dc !in MtConst.DC_DEFAULT_IPS) {
            ProxyLog.w("[$label] H2 unsupported DC$dc -> existing WS route")
            return null
        }
        for (baseDomain in balancer.domainsForDc(dc)) {
            val host = "kws$dc.$baseDomain"
            val hostLock = synchronized(state) { hostLocks.getOrPut(host) { ReentrantLock() } }
            val waitNanos = ((deadline - CfH2Clock.now()) * 1e9).toLong()
            try {
                if (waitNanos <= 0 || !hostLock.tryLock(waitNanos, TimeUnit.NANOSECONDS)) throw SetupTimeout()
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                throw SetupTimeout()
            }
            try {
                val channel = openOn(host, baseDomain, dc, label, deadline)
                if (channel != null) return channel
            } finally {
                hostLock.unlock()
            }
        }
        ProxyLog.d("[$label] H2 DC$dc unavailable; using WS")
        return null
    }

    /** A channel on [host]'s lane, preflighting a new lane first; null means try the next domain. */
    private fun openOn(host: String, baseDomain: String, dc: Int, label: String, deadline: Double): CfH2Channel? {
        if (closed) throw CfH2ConnectionError("H2 pool closed")
        var lane = synchronized(state) { lanes[host] }
        val hostFailed = synchronized(state) { failedUntil[host] ?: 0.0 }
        if (CfH2Clock.now() < maxOf(hostFailed, lane?.failedUntil ?: 0.0)) return null
        if (lane == null) {
            val laneId = synchronized(state) { ++nextLane }
            val fresh = CfH2Lane(host, laneId, ctx, tuning, transportFactory(host))
            try {
                val leftMillis = ((deadline - CfH2Clock.now()) * 1000).toLong()
                if (leftMillis <= 0) throw InterruptedIOException("timeout")
                fresh.preflight(leftMillis)
            } catch (e: IOException) {
                fresh.close()
                if (e is InterruptedIOException || CfH2Clock.now() >= deadline) throw SetupTimeout()
                ctx.stats.h2Errors.incrementAndGet()
                synchronized(state) { failedUntil[host] = CfH2Clock.now() + tuning.domainCooldown }
                ProxyLog.w("[$label] H2 lane=${fresh.laneId} preflight failed host=$host: ${errName(e)}: ${e.message}")
                return null
            } catch (e: RuntimeException) {
                fresh.close()
                throw e
            }
            if (closed) {
                fresh.close()
                throw CfH2ConnectionError("H2 pool closed during preflight")
            }
            synchronized(state) { lanes[host] = fresh }
            lane = fresh
        }
        val channelId = synchronized(state) { ++nextChannel }
        val channel = CfH2Channel(lane, channelId, label)
        balancer.updateDomainForDc(dc, baseDomain)
        val (channels, tcp) = lane.lock.withLock { lane.channels.size to lane.tcpConnections }
        ProxyLog.i(
            "[$label] ROUTE DC$dc media -> H2 lane=${lane.laneId} channel=$channelId host=$host " +
                "channels=$channels tcp_connections=$tcp"
        )
        return channel
    }

    private fun laneList(): List<CfH2Lane> = synchronized(state) { lanes.values.toList() }

    /** The periodic per-lane stats lines (upstream log_stats; debug level, as upstream). */
    fun logStats() {
        for (lane in laneList()) {
            if (lane.lock.withLock { lane.channels.isNotEmpty() }) ProxyLog.d { "H2 STATS " + lane.summary() }
        }
    }

    /** The debug flow lines (upstream log_flow), only when ProxyLog.verbose. */
    fun logFlow() {
        if (!ProxyLog.verbose) return
        val now = CfH2Clock.now()
        for (lane in laneList()) lane.logFlow(now)
    }

    override fun close() {
        closed = true
        val all = synchronized(state) { lanes.values.toList().also { lanes.clear() } }
        for (lane in all) lane.close()
    }
}

/**
 * Carries one client connection over [channel] until either side ends (upstream bridge_h2).
 * [clientIn] and [clientOut] are the client's streams already past the 64-byte init; crypto.cltDec
 * decrypts the client's bytes and crypto.cltEnc encrypts bytes to it. [protoTag] is the client's
 * transport tag (MtConst.PROTO_TAG_*). An MTProto transport error from the endpoint (HTTP 403, 404,
 * 429, 444 or a negative 4-byte reply) is sent to the client as its error code before closing.
 * Closes the channel and both client streams before returning.
 */
fun bridgeH2(
    ctx: ProxyContext,
    clientIn: InputStream,
    clientOut: OutputStream,
    channel: CfH2Channel,
    crypto: CryptoCtx,
    protoTag: ByteArray,
    label: String,
) {
    CfH2Bridge(ctx, clientIn, clientOut, channel, crypto, protoTag, label).run()
}

private class CfH2Bridge(
    private val ctx: ProxyContext,
    private val clientIn: InputStream,
    private val clientOut: OutputStream,
    private val channel: CfH2Channel,
    private val crypto: CryptoCtx,
    private val tag: ByteArray,
    private val label: String,
) {
    private val lane = channel.lane
    private val t = lane.t
    private val writeLock = ReentrantLock()
    @Volatile private var stopping = false

    private class Outcome(val error: Throwable?)

    private fun writeNative(data: ByteArray) {
        writeLock.withLock {
            if (stopping) throw CfH2NativeDeliveryError("H2 bridge stopping")
            writeNow(data)
        }
    }

    /** Caller holds [writeLock]. */
    private fun writeNow(data: ByteArray) {
        try {
            clientOut.write(crypto.cltEnc.update(data))
            clientOut.flush()
        } catch (e: IOException) {
            throw CfH2NativeDeliveryError(e.message ?: errName(e))
        }
    }

    private fun upload() {
        val decrypt: (ByteArray) -> ByteArray = { crypto.cltDec.update(it) }
        while (true) {
            val packet = try {
                CfH2Framing.readPacket(clientIn, decrypt, tag, t.maxPacket, t.maxPlainPadding)
            } catch (e: EOFException) {
                throw e
            } catch (e: CfH2ValueError) {
                throw e
            } catch (e: IOException) {
                throw CfH2NativeDeliveryError(e.message ?: errName(e))
            }
            channel.send(packet.body, packet.quick)
        }
    }

    private fun download() {
        while (true) {
            val body = channel.receive()
            if (channel.closed) throw CfH2NativeDeliveryError("H2 channel closed before native response")
            lane.lock.withLock { channel.deliveringSince = CfH2Clock.now() }
            try {
                writeNative(CfH2Framing.encodeReply(body, tag, t.maxPacket))
            } finally {
                lane.lock.withLock { channel.deliveringSince = null }
            }
            lane.lock.withLock {
                channel.down += body.size
                channel.lastProgress = CfH2Clock.now()
                channel.wakeReceiver()
            }
            ctx.stats.bytesDown.addAndGet(body.size.toLong())
        }
    }

    fun run() {
        val outcomes = LinkedBlockingQueue<Outcome>()
        val workers = ArrayList<Future<*>>()
        try {
            for (work in listOf(::upload, ::download, channel::recover)) {
                workers += ctx.executor.submit {
                    val error = try {
                        work()
                        null
                    } catch (e: Throwable) {
                        e
                    }
                    outcomes.put(Outcome(error))
                }
            }
            val first = try {
                outcomes.take()
            } finally {
                stopping = true
                channel.stopRecovery()
            }
            val code = channel.transportError
            if (code != null) {
                if (writeLock.tryLock(5, TimeUnit.SECONDS)) {
                    try {
                        writeNow(CfH2Framing.encodeReply(CfH2Framing.int32le(code), tag, t.maxPacket))
                    } finally {
                        writeLock.unlock()
                    }
                    lane.lock.withLock { channel.down += 4 }
                    ctx.stats.bytesDown.addAndGet(4)
                }
            } else {
                first.error?.let { throw it }
            }
        } catch (_: EOFException) {
            ProxyLog.d { "[$label] H2 channel=${channel.channelId} native EOF" }
        } catch (e: CfH2NativeDeliveryError) {
            ProxyLog.d { "[$label] H2 channel=${channel.channelId} native closed: ${e.message}" }
        } catch (e: IOException) {
            if (!channel.closed) {
                ProxyLog.w("[$label] H2 channel=${channel.channelId} bridge ended: ${errName(e)}: ${e.message}")
            }
        } catch (_: RejectedExecutionException) {
            ProxyLog.d { "[$label] H2 channel=${channel.channelId} proxy stopping" }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } catch (e: Exception) {
            ProxyLog.e("[$label] H2 channel=${channel.channelId} bridge failed: $e")
        } finally {
            stopping = true
            channel.close()
            clientIn.closeQuietly()
            clientOut.closeQuietly()
            for (worker in workers) {
                try {
                    worker.get(2, TimeUnit.SECONDS)
                } catch (_: Exception) {
                }
            }
        }
    }
}
