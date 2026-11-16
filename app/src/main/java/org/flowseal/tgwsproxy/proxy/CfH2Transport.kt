package org.flowseal.tgwsproxy.proxy

import okhttp3.Call
import okhttp3.Connection
import okhttp3.ConnectionPool
import okhttp3.EventListener
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.Response
import okio.BufferedSink
import java.io.ByteArrayInputStream
import java.io.Closeable
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/** The origin did not negotiate HTTP/2; not retried by OkHttp, cools the domain down. */
internal class CfH2NotHttp2(message: String) : java.net.ProtocolException(message)

/** Points in one HTTP request that the lane traces (upstream: httpx/httpcore trace events). */
internal interface CfH2Events {
    /** A new TCP connection is being opened for the request. */
    fun connectStart() {}
    fun requestHeadersStart() {}
    /** The whole request body has been handed to the HTTP/2 stream. */
    fun requestBodyEnd() {}
}

/** The answer to one request; [body] streams the response body. Close it when done. */
internal class CfH2Response(
    val status: Int,
    /** "HTTP/2" or "HTTP/1.1". */
    val protocol: String,
    private val headerLookup: (String) -> String?,
    val body: InputStream,
    private val onClose: () -> Unit,
) : Closeable {
    /** A response header, case-insensitive. */
    fun header(name: String): String? = headerLookup(name)
    override fun close() = onClose()
}

internal interface CfH2Call {
    /**
     * Sends the request and blocks until the response headers arrive. With [timeoutMillis] > 0 the
     * whole call is cancelled after that long (InterruptedIOException).
     */
    fun execute(timeoutMillis: Long = 0): CfH2Response

    /** Aborts the call from any thread; a blocked execute() or body read then throws IOException. */
    fun cancel()
}

/** HTTP requests to https://<host>/api of one lane (upstream h2_transport.H2Transport). */
internal interface CfH2Transport : Closeable {
    fun newCall(method: String, body: ByteArray?, events: CfH2Events?): CfH2Call
}

/**
 * [CfH2Transport] on OkHttp: HTTP/2 negotiated by ALPN, every request of a lane multiplexed as a
 * stream of one TLS connection, and nothing sent on a connection that is not HTTP/2.
 */
internal class OkHttpCfH2Transport(host: String, base: OkHttpClient = sharedClient) : CfH2Transport {
    private val url: HttpUrl = "https://$host/api".toHttpUrl()
    private val pool = ConnectionPool(2, 5, TimeUnit.MINUTES)
    private val client: OkHttpClient = base.newBuilder()
        .connectionPool(pool)
        .eventListenerFactory(EventsFactory)
        .addNetworkInterceptor(RequireHttp2)
        .build()
    private val active: MutableSet<Call> = Collections.newSetFromMap(ConcurrentHashMap())
    @Volatile private var closed = false

    /**
     * Held by one call from execute() until OkHttp hands it a connection (upstream: the
     * transport's connect_lock). With a pooled connection that is immediate; without one, the
     * other calls wait for the new connection and share it instead of each opening its own
     * TCP and TLS connection, which OkHttp would do and only then coalesce.
     */
    private val connectGate = Semaphore(1)

    override fun newCall(method: String, body: ByteArray?, events: CfH2Events?): CfH2Call {
        val state = CallState(events)
        val builder = Request.Builder().url(url).header("Accept-Encoding", "identity")
        if (method == "HEAD") builder.head() else builder.method(method, body?.let { OneShotBody(it) })
        builder.tag(CallState::class.java, state)
        return OkCall(client.newCall(builder.build()), state)
    }

    override fun close() {
        closed = true
        for (call in active.toList()) call.cancel()
        pool.evictAll()
    }

    private inner class CallState(val events: CfH2Events?) {
        private val gateHeld = AtomicBoolean(false)

        /** Waits for [connectGate]; gives up after the connect timeout so a stuck opener cannot hold everyone. */
        fun acquireGate(call: Call) {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(client.connectTimeoutMillis.toLong())
            while (!call.isCanceled() && System.nanoTime() < deadline) {
                if (connectGate.tryAcquire(20, TimeUnit.MILLISECONDS)) {
                    gateHeld.set(true)
                    return
                }
            }
        }

        fun releaseGate() {
            if (gateHeld.compareAndSet(true, false)) connectGate.release()
        }
    }

    private inner class OkCall(private val call: Call, private val state: CallState) : CfH2Call {
        override fun execute(timeoutMillis: Long): CfH2Response {
            if (timeoutMillis > 0) call.timeout().timeout(timeoutMillis, TimeUnit.MILLISECONDS)
            if (closed) throw IOException("H2 transport closed")
            active.add(call)
            if (closed) call.cancel()
            val response: Response = try {
                try {
                    state.acquireGate(call)
                } catch (e: InterruptedException) {
                    Thread.currentThread().interrupt()
                    throw InterruptedIOException("interrupted")
                }
                call.execute()
            } catch (e: Throwable) {
                finished()
                throw e
            } finally {
                state.releaseGate()
            }
            return CfH2Response(
                response.code,
                protocolName(response.protocol),
                { name -> response.header(name) },
                response.body?.byteStream() ?: ByteArrayInputStream(ByteArray(0)),
            ) {
                response.closeQuietly()
                finished()
            }
        }

        override fun cancel() = call.cancel()

        private fun finished() {
            active.remove(call)
            if (closed) pool.evictAll()
        }
    }

    private object EventsFactory : EventListener.Factory {
        override fun create(call: Call): EventListener {
            val state = call.request().tag(CallState::class.java) ?: return EventListener.NONE
            val events = state.events
            return object : EventListener() {
                override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
                    events?.connectStart()
                }

                override fun connectionAcquired(call: Call, connection: Connection) = state.releaseGate()

                override fun requestHeadersStart(call: Call) {
                    events?.requestHeadersStart()
                }

                override fun requestBodyEnd(call: Call, byteCount: Long) {
                    events?.requestBodyEnd()
                }

                override fun callFailed(call: Call, ioe: IOException) = state.releaseGate()
            }
        }
    }

    /** Upstream's transport refuses an origin that did not negotiate h2 before sending anything. */
    private object RequireHttp2 : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val connection = chain.connection()
            val protocol = connection?.protocol()
            if (protocol != Protocol.HTTP_2 && protocol != Protocol.H2_PRIOR_KNOWLEDGE) {
                connection?.socket().closeQuietly()
                throw CfH2NotHttp2("CF /api negotiated ${protocolName(protocol)}, not HTTP/2")
            }
            return chain.proceed(chain.request())
        }
    }

    /**
     * A POST body OkHttp must never send twice: with one-shot bodies OkHttp still tries the
     * host's other addresses and a refused stream (nothing reached the server), but neither
     * resends a request that may have arrived nor follows up a response (408, 503, 421).
     * A failed request closes its native channel, as upstream's does; resending is the
     * channel's replay logic's decision.
     */
    private class OneShotBody(private val bytes: ByteArray) : RequestBody() {
        override fun contentType() = OCTET_STREAM
        override fun contentLength() = bytes.size.toLong()
        override fun isOneShot() = true
        override fun writeTo(sink: BufferedSink) {
            sink.write(bytes)
        }
    }

    companion object {
        private val OCTET_STREAM = "application/octet-stream".toMediaType()

        /**
         * Settings shared by every lane (upstream: one verified TLS context for all lanes):
         * no proxy, no redirects; connection-level retries stay on (see [OneShotBody]).
         */
        fun clientBuilder(): OkHttpClient.Builder = OkHttpClient.Builder()
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .proxy(Proxy.NO_PROXY)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(true)
            .connectTimeout(8, TimeUnit.SECONDS)
            .readTimeout(CfH2Tuning.REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(CfH2Tuning.REQUEST_TIMEOUT_SECONDS, TimeUnit.SECONDS)

        val sharedClient: OkHttpClient by lazy { clientBuilder().build() }

        fun protocolName(protocol: Protocol?): String = when (protocol) {
            Protocol.HTTP_2, Protocol.H2_PRIOR_KNOWLEDGE -> CfH2Tuning.HTTP2
            Protocol.HTTP_1_1 -> "HTTP/1.1"
            Protocol.HTTP_1_0 -> "HTTP/1.0"
            null -> "no connection"
            else -> protocol.toString()
        }
    }
}
