package org.flowseal.tgwsproxy.proxy

import java.io.BufferedInputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/**
 * The local MTProto proxy (upstream proxy/tg_ws_proxy.py). A Telegram client connects with the
 * secret; the proxy reads the DC from the client's obfuscated init, opens its own obfuscated
 * connection to that DC over a pooled WebSocket, or a fallback, and re-encrypts between the two.
 *
 * start() binds synchronously and throws IOException (BindException when the port is taken or
 * the address is not local), then accepts clients on its own threads. stop() closes the
 * listener and every connection.
 */
class ProxyServer(val settings: ProxySettings) {

    companion object {
        private const val HANDSHAKE_TIMEOUT_MS = 10_000
        private const val BAD_HANDSHAKE_DRAIN_TIMEOUT_MS = 10_000L
        private const val BAD_HANDSHAKE_DRAIN_LIMIT = 64 * 1024
        private const val LISTENER_RESTART_DELAY_MS = 1_000L
        private const val STATS_INTERVAL_S = 60L
        private const val FLOW_INTERVAL_S = 5L
    }

    val ctx = ProxyContext(settings)
    val stats: Stats get() = ctx.stats

    private val secret = settings.secret
    private val wsPool = WsPool(ctx)
    private val cfWorkerPool = CfWorkerPool(ctx)
    private val h2Pool: CfH2Pool? = if (settings.h2Enabled) CfH2Pool(ctx) else null
    private val bridge = Bridge(ctx, cfWorkerPool, h2Pool)
    private var domainRefresh: java.util.concurrent.ScheduledFuture<*>? = null
    private val clients = ConcurrentHashMap.newKeySet<Socket>()

    @Volatile private var serverSocket: ServerSocket? = null
    @Volatile private var running = false
    val isRunning: Boolean get() = running

    @Throws(IOException::class)
    fun start() {
        if (running) return
        RawWebSocket.socketBufferSize = settings.bufferSize
        // Probe before listening, so a masking domain that resolves to this proxy fails fast
        // instead of answering itself
        FakeTls.profiledAppdataLen = null
        if (settings.fakeTlsDomain.isNotEmpty()) FakeTls.profileMaskingSite(settings.fakeTlsDomain)
        serverSocket = bind()
        running = true

        logBanner()
        startBackground()

        Thread({ acceptLoop() }, "tgws-accept").apply { isDaemon = true; start() }
        ctx.scheduler.scheduleWithFixedDelay(
            {
                ProxyLog.i("stats: ${stats.summary()}")
                runCatching { h2Pool?.logStats() }
            },
            STATS_INTERVAL_S, STATS_INTERVAL_S, TimeUnit.SECONDS
        )
        if (h2Pool != null) {
            ctx.scheduler.scheduleWithFixedDelay({ runCatching { h2Pool?.logFlow() } }, FLOW_INTERVAL_S, FLOW_INTERVAL_S, TimeUnit.SECONDS)
        }
        wsPool.warmup()
        cfWorkerPool.warmup()
    }

    /** What has to run before clients arrive: the domain lists and pools of later features. */
    private fun startBackground() {
        if (settings.cfproxyUserDomains.isNotEmpty()) {
            ctx.balancer.updateDomainsList(settings.cfproxyUserDomains)
        } else {
            domainRefresh = CfProxyDomains.startRefresh(ctx)
        }
    }

    private fun bind(): ServerSocket {
        val ss = ServerSocket()
        try {
            ss.reuseAddress = true
            ss.bind(InetSocketAddress(settings.host, settings.port), 128)
        } catch (e: IOException) {
            ss.closeQuietly()
            throw e
        }
        return ss
    }

    fun stop() {
        if (!running) return
        running = false
        serverSocket.closeQuietly()
        serverSocket = null
        for (c in clients) c.closeQuietly()
        clients.clear()
        stopBackground()
        wsPool.close()
        ctx.shutdown()
        ProxyLog.i("Proxy stopped. Final stats: ${stats.summary()}")
    }

    private fun stopBackground() {
        domainRefresh?.cancel(true)
        cfWorkerPool.close()
        h2Pool?.close()
    }

    private fun logBanner() {
        val line = "=".repeat(60)
        ProxyLog.i(line)
        ProxyLog.i("  Telegram MTProto WS Bridge Proxy")
        ProxyLog.i("  Listening on   ${settings.host}:${settings.port}")
        ProxyLog.i("  Secret:        ${settings.secretHex}")
        if (settings.fakeTlsDomain.isNotEmpty()) ProxyLog.i("  Fake TLS:      ${settings.fakeTlsDomain}")
        ProxyLog.i("  Target DC IPs:")
        for (dc in settings.dcRedirects.keys.sorted()) ProxyLog.i("    DC$dc: ${settings.dcRedirects[dc]}")
        if (settings.fallbackCfproxy) {
            val user = settings.cfproxyUserDomains.joinToString(", ").ifEmpty { "auto" }
            ProxyLog.i("  CF proxy:      enabled ($user)")
        }
        if (settings.cfproxyWorkerDomains.isNotEmpty()) {
            ProxyLog.i("  CF worker:     enabled (${settings.cfproxyWorkerDomains.joinToString(", ")})")
        }
        if (h2Pool != null) ProxyLog.i("  CF H2 media:   enabled")
        if (settings.disableSecure) ProxyLog.i("  No secure:     enabled (port 80 for CF proxy/worker)")
        if (settings.forceTestDc) ProxyLog.i("  Test DCs:      forced")
        ProxyLog.i(line)
        ProxyLog.i("  Connect:")
        ProxyLog.i("    ${settings.proxyLink()}")
        ProxyLog.i(line)
    }

    /** Accepts until stopped; a listener that dies is reopened (upstream's listener watchdog). */
    private fun acceptLoop() {
        while (running) {
            val ss = serverSocket ?: break
            try {
                val sock = ss.accept()
                if (!running) {
                    sock.closeQuietly()
                    break
                }
                try {
                    ctx.executor.execute { handleClient(sock) }
                } catch (_: RejectedExecutionException) {
                    sock.closeQuietly()
                }
            } catch (e: IOException) {
                if (!running) break
                ProxyLog.w("Listening socket died (${errStr(e)}), restarting server")
                ss.closeQuietly()
                try {
                    Thread.sleep(LISTENER_RESTART_DELAY_MS)
                } catch (_: InterruptedException) {
                    break
                }
                if (!running) break
                try {
                    serverSocket = bind()
                    ProxyLog.w("Server restored, listening on ${settings.host}:${settings.port}")
                } catch (e2: IOException) {
                    ProxyLog.e("Failed to restart server: ${errStr(e2)}")
                    running = false
                    break
                }
            }
        }
    }

    private fun handleClient(sock: Socket) {
        stats.connectionsTotal.incrementAndGet()
        stats.connectionsActive.incrementAndGet()
        clients.add(sock)
        var label = "${sock.inetAddress?.hostAddress}:${sock.port}"
        try {
            sock.tcpNoDelay = true
            try {
                sock.sendBufferSize = settings.bufferSize
                sock.receiveBufferSize = settings.bufferSize
            } catch (_: Exception) {
            }
            sock.soTimeout = HANDSHAKE_TIMEOUT_MS
            val rawIn: InputStream = BufferedInputStream(sock.getInputStream(), 65536)
            val rawOut: OutputStream = sock.getOutputStream()

            val init = readClientInit(rawIn, rawOut, label) ?: return
            val (handshake, cIn, cOut) = init

            val hs = MtProto.tryHandshake(handshake, secret)
            if (hs == null) {
                stats.connectionsBad.incrementAndGet()
                ProxyLog.w("[$label] bad handshake (wrong secret or proto)")
                drainBadHandshake(cIn)
                return
            }
            sock.soTimeout = 0

            var dc = hs.dc
            val isMedia = hs.isMedia
            val isTestDc = settings.forceTestDc || dc >= 10000
            if (dc >= 10000) {
                ProxyLog.i("[$label] test DC$dc -> DC${dc - 10000}")
                dc -= 10000
            }
            val protoInt = MtConst.protoInt(hs.protoTag)
            val dcIdx = if (isMedia) -dc else dc
            ProxyLog.d {
                "[$label] handshake ok: DC$dc${if (isMedia) " media" else ""} proto=0x%08X".format(protoInt)
            }

            val relayInit = MtProto.generateRelayInit(hs.protoTag, dcIdx)
            val crypto = MtProto.buildCryptoCtx(hs.prekeyAndIv, secret, relayInit)
            val client = ClientConn(cIn, cOut, label, crypto) { sock.close() }
            val mediaTag = if (isMedia) " media" else ""

            val ws = wsPool.get(dc, isMedia, isTestDc)
            if (ws == null) {
                ProxyLog.i("[$label] DC$dc$mediaTag WS pool unavailable -> fallback")
                val ok = bridge.doFallback(
                    client, relayInit, dc, isTestDc, isMedia,
                    MsgSplitter(protoInt), hs.protoTag,
                )
                if (ok) ProxyLog.i("[$label] DC$dc$mediaTag fallback closed")
                else ProxyLog.w("[$label] DC$dc$mediaTag no fallback available")
                return
            }

            ProxyLog.i("[$label] DC$dc$mediaTag -> WS pool hit")
            stats.connectionsWs.incrementAndGet()
            ws.send(relayInit)
            bridge.bridgeWsReencrypt(client, ws, dc, isMedia, MsgSplitter(protoInt))
        } catch (_: SocketTimeoutException) {
            ProxyLog.w("[$label] timeout during handshake")
        } catch (_: EOFException) {
            ProxyLog.d { "[$label] client disconnected" }
        } catch (e: IOException) {
            if (running) ProxyLog.d { "[$label] connection error: ${errStr(e)}" }
        } catch (e: Exception) {
            ProxyLog.e("[$label] unexpected: ${errStr(e)}")
        } finally {
            stats.connectionsActive.decrementAndGet()
            clients.remove(sock)
            sock.closeQuietly()
        }
    }

    private data class ClientInit(val handshake: ByteArray, val input: InputStream, val output: OutputStream)

    /** The client's 64-byte obfuscated init, and the streams to keep using. */
    private fun readClientInit(input: InputStream, output: OutputStream, label: String): ClientInit? {
        val first = input.read()
        if (first < 0) {
            ProxyLog.d { "[$label] client disconnected before handshake" }
            return null
        }
        val masking = settings.fakeTlsDomain
        if (first == FakeTls.TLS_RECORD_HANDSHAKE && masking.isNotEmpty()) {
            val (tlsIn, tlsOut) = FakeTls.accept(first, input, output, secret, masking, label, ctx) ?: return null
            return ClientInit(tlsIn.readExactly(MtConst.HANDSHAKE_LEN), tlsIn, tlsOut)
        }
        if (masking.isNotEmpty()) {
            // With Fake TLS on, anything but TLS is a browser or a prober: send it to the real site
            ProxyLog.d { "[$label] non-TLS byte 0x%02X -> HTTP redirect".format(first) }
            output.write(
                ("HTTP/1.1 301 Moved Permanently\r\nLocation: https://$masking/\r\n" +
                    "Content-Length: 0\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
            )
            output.flush()
            return null
        }
        val rest = input.readExactly(MtConst.HANDSHAKE_LEN - 1)
        return ClientInit(byteArrayOf(first.toByte()) + rest, input, output)
    }

    private fun drainBadHandshake(input: InputStream) {
        val deadline = System.nanoTime() / 1_000_000 + BAD_HANDSHAKE_DRAIN_TIMEOUT_MS
        var remaining = BAD_HANDSHAKE_DRAIN_LIMIT
        val buf = ByteArray(4096)
        try {
            while (remaining > 0 && System.nanoTime() / 1_000_000 < deadline) {
                val n = input.read(buf, 0, minOf(buf.size, remaining))
                if (n < 0) break
                remaining -= n
            }
        } catch (_: Exception) {
        }
    }
}
