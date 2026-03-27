package org.flowseal.tgwsproxy.proxy

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * SOCKS5 proxy server that bridges Telegram traffic through WebSocket.
 * Complete port of the Python tg_ws_proxy.py logic.
 */
class ProxyServer(
    private val host: String = "127.0.0.1",
    private val port: Int = 1080,
    private val dcOpt: Map<Int, String> = mapOf(2 to "149.154.167.220", 4 to "149.154.167.220"),
    private val poolSize: Int = 4,
    private val bufKb: Int = 256,
    private val onLog: ((String) -> Unit)? = null
) {
    private val TAG = "ProxyServer"

    private val running = AtomicBoolean(false)
    private var serverSocket: ServerSocket? = null
    private var executor: ExecutorService? = null
    private val wsPool = WsPool(poolSize)
    val stats: Stats get() = wsPool.stats

    // WS blacklist: DCs where WS always returns 302
    private val wsBlacklist = ConcurrentHashMap.newKeySet<Pair<Int, Boolean>>()

    // Failure cooldown tracking
    private val dcFailUntil = ConcurrentHashMap<Pair<Int, Boolean>, Long>()
    private val DC_FAIL_COOLDOWN = 30_000L  // 30 seconds
    private val WS_FAIL_TIMEOUT = 2000      // 2 seconds

    private val bufSize = bufKb * 1024

    fun start() {
        if (running.getAndSet(true)) return

        executor = Executors.newCachedThreadPool { r ->
            Thread(r).apply {
                isDaemon = true
                name = "proxy-worker"
            }
        }

        Thread({
            try {
                serverSocket = ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(host, port))
                }
                log("Telegram WS Bridge Proxy listening on $host:$port")
                log("Target DCs: ${dcOpt.entries.joinToString { "DC${it.key}:${it.value}" }}")

                wsPool.warmup(dcOpt)

                while (running.get()) {
                    try {
                        val client = serverSocket!!.accept()
                        client.tcpNoDelay = true
                        client.setSendBufferSize(bufSize)
                        client.setReceiveBufferSize(bufSize)
                        executor?.execute { handleClient(client) }
                    } catch (e: Exception) {
                        if (running.get()) {
                            Log.e(TAG, "Accept error: $e")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Server start error: $e")
                log("Failed to start: $e")
            }
        }, "proxy-server").start()
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        try { serverSocket?.close() } catch (_: Exception) {}
        wsPool.shutdown()
        executor?.shutdownNow()
        serverSocket = null
        executor = null
        log("Proxy stopped")
    }

    val isRunning: Boolean get() = running.get()

    private fun log(msg: String) {
        Log.i(TAG, msg)
        onLog?.invoke(msg)
    }

    // --- SOCKS5 reply helpers ---

    private fun socks5Reply(status: Int): ByteArray =
        byteArrayOf(0x05, status.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0)

    // --- Client handling ---

    private fun handleClient(client: Socket) {
        stats.connectionsTotal.incrementAndGet()
        val label = "${client.inetAddress.hostAddress}:${client.port}"

        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // SOCKS5 greeting
            val hdr = readExactly(input, 2)
            if (hdr[0].toInt() != 5) {
                Log.d(TAG, "[$label] not SOCKS5 (ver=${hdr[0]})")
                client.close()
                return
            }
            val nmethods = hdr[1].toInt() and 0xFF
            readExactly(input, nmethods)
            output.write(byteArrayOf(0x05, 0x00)) // no-auth
            output.flush()

            // SOCKS5 CONNECT request
            val req = readExactly(input, 4)
            val cmd = req[1].toInt() and 0xFF
            val atyp = req[3].toInt() and 0xFF

            if (cmd != 1) {
                output.write(socks5Reply(0x07))
                output.flush()
                client.close()
                return
            }

            val dst: String
            when (atyp) {
                1 -> { // IPv4
                    val raw = readExactly(input, 4)
                    dst = InetAddress.getByAddress(raw).hostAddress!!
                }
                3 -> { // domain
                    val dlen = (readExactly(input, 1)[0].toInt() and 0xFF)
                    dst = String(readExactly(input, dlen), Charsets.US_ASCII)
                }
                4 -> { // IPv6
                    val raw = readExactly(input, 16)
                    dst = InetAddress.getByAddress(raw).hostAddress!!
                }
                else -> {
                    output.write(socks5Reply(0x08))
                    output.flush()
                    client.close()
                    return
                }
            }

            val portBytes = readExactly(input, 2)
            val dstPort = ((portBytes[0].toInt() and 0xFF) shl 8) or (portBytes[1].toInt() and 0xFF)

            // IPv6 not supported
            if (dst.contains(':')) {
                Log.e(TAG, "[$label] IPv6 address: $dst:$dstPort — not supported")
                output.write(socks5Reply(0x05))
                output.flush()
                client.close()
                return
            }

            // Non-Telegram IP → direct passthrough
            if (!TelegramDC.isTelegramIp(dst)) {
                stats.connectionsPassthrough.incrementAndGet()
                Log.d(TAG, "[$label] passthrough -> $dst:$dstPort")
                try {
                    val remote = Socket()
                    remote.connect(InetSocketAddress(dst, dstPort), 10000)
                    remote.tcpNoDelay = true

                    output.write(socks5Reply(0x00))
                    output.flush()

                    bridgeTcp(input, output, remote.getInputStream(), remote.getOutputStream(),
                        label, client, remote)
                } catch (e: Exception) {
                    Log.w(TAG, "[$label] passthrough failed: $e")
                    output.write(socks5Reply(0x05))
                    output.flush()
                    client.close()
                }
                return
            }

            // Telegram DC — accept SOCKS, read init
            output.write(socks5Reply(0x00))
            output.flush()

            val init: ByteArray
            try {
                init = readExactly(input, 64)
            } catch (_: Exception) {
                Log.d(TAG, "[$label] client disconnected before init")
                client.close()
                return
            }

            // HTTP transport → reject
            if (TelegramDC.isHttpTransport(init)) {
                stats.connectionsHttpRejected.incrementAndGet()
                Log.d(TAG, "[$label] HTTP transport to $dst:$dstPort (rejected)")
                client.close()
                return
            }

            // Extract DC ID
            var result = TelegramDC.dcFromInit(init)
            var dc = result.dc
            var isMedia = result.isMedia
            val proto = result.proto
            var initData = init
            var initPatched = false

            // Android with useSecret=0 has random dc_id — patch it
            if (dc == null && dst in TelegramDC.IP_TO_DC) {
                val (resolvedDc, resolvedMedia) = TelegramDC.IP_TO_DC[dst]!!
                dc = resolvedDc
                isMedia = resolvedMedia
                if (dc in dcOpt) {
                    initData = TelegramDC.patchInitDc(init, if (isMedia) -dc else dc)
                    initPatched = true
                }
            }

            if (dc == null || dc !in dcOpt) {
                Log.w(TAG, "[$label] unknown DC$dc for $dst:$dstPort -> TCP passthrough")
                tcpFallback(input, output, dst, dstPort, initData, label, client, dc, isMedia)
                return
            }

            val dcKey = dc to isMedia
            val now = System.currentTimeMillis()
            val mediaTag = if (isMedia) " media" else ""

            // WS blacklist check
            if (dcKey in wsBlacklist) {
                Log.d(TAG, "[$label] DC$dc$mediaTag WS blacklisted -> TCP $dst:$dstPort")
                tcpFallback(input, output, dst, dstPort, initData, label, client, dc, isMedia)
                return
            }

            // Try WebSocket
            val failUntil = dcFailUntil[dcKey] ?: 0L
            val wsTimeout = if (now < failUntil) WS_FAIL_TIMEOUT else 10000

            val domains = TelegramDC.wsDomains(dc, isMedia)
            val target = dcOpt[dc]!!
            var ws: RawWebSocket? = null
            var wsFailedRedirect = false
            var allRedirects = true

            // Try pool first
            ws = wsPool.get(dc, isMedia, target, domains)
            if (ws != null) {
                log("[$label] DC$dc$mediaTag ($dst:$dstPort) -> pool hit via $target")
            } else {
                // Fresh connection
                for (domain in domains) {
                    val url = "wss://$domain/apiws"
                    log("[$label] DC$dc$mediaTag ($dst:$dstPort) -> $url via $target")
                    try {
                        ws = RawWebSocket.connect(target, domain, timeoutMs = wsTimeout)
                        allRedirects = false
                        break
                    } catch (e: WsHandshakeError) {
                        stats.wsErrors.incrementAndGet()
                        if (e.isRedirect) {
                            wsFailedRedirect = true
                            Log.w(TAG, "[$label] DC$dc$mediaTag got ${e.statusCode} from $domain -> ${e.location}")
                            continue
                        } else {
                            allRedirects = false
                            Log.w(TAG, "[$label] DC$dc$mediaTag WS handshake: ${e.statusLine}")
                        }
                    } catch (e: Exception) {
                        stats.wsErrors.incrementAndGet()
                        allRedirects = false
                        Log.w(TAG, "[$label] DC$dc$mediaTag WS connect failed: $e")
                    }
                }
            }

            // WS failed → fallback
            if (ws == null) {
                if (wsFailedRedirect && allRedirects) {
                    wsBlacklist.add(dcKey)
                    Log.w(TAG, "[$label] DC$dc$mediaTag blacklisted for WS (all 302)")
                } else {
                    dcFailUntil[dcKey] = now + DC_FAIL_COOLDOWN
                    log("[$label] DC$dc$mediaTag WS cooldown for ${DC_FAIL_COOLDOWN / 1000}s")
                }
                log("[$label] DC$dc$mediaTag -> TCP fallback to $dst:$dstPort")
                tcpFallback(input, output, dst, dstPort, initData, label, client, dc, isMedia)
                return
            }

            // WS success
            dcFailUntil.remove(dcKey)
            stats.connectionsWs.incrementAndGet()

            var splitter: MsgSplitter? = null
            if (proto != null && (initPatched || isMedia || proto != TelegramDC.PROTO_INTERMEDIATE)) {
                try {
                    splitter = MsgSplitter(initData, proto)
                    Log.d(TAG, "[$label] MsgSplitter activated for proto 0x${proto.toUInt().toString(16)}")
                } catch (_: Exception) {}
            }

            // Send init packet
            ws.send(initData)

            // Bidirectional bridge
            bridgeWs(input, output, ws, label, client, dc, dst, dstPort, isMedia, splitter)

        } catch (e: Exception) {
            Log.d(TAG, "[$label] error: $e")
        } finally {
            try { client.close() } catch (_: Exception) {}
        }
    }

    // --- TCP fallback ---

    private fun tcpFallback(
        clientIn: InputStream, clientOut: OutputStream,
        dst: String, port: Int, init: ByteArray, label: String,
        clientSocket: Socket, dc: Int?, isMedia: Boolean
    ) {
        try {
            val remote = Socket()
            remote.connect(InetSocketAddress(dst, port), 10000)
            remote.tcpNoDelay = true

            stats.connectionsTcpFallback.incrementAndGet()
            remote.getOutputStream().write(init)
            remote.getOutputStream().flush()

            bridgeTcp(clientIn, clientOut, remote.getInputStream(), remote.getOutputStream(),
                label, clientSocket, remote)

            log("[$label] DC$dc${if (isMedia) "m" else ""} TCP fallback closed")
        } catch (e: Exception) {
            Log.w(TAG, "[$label] TCP fallback to $dst:$port failed: $e")
        }
    }

    // --- Bidirectional TCP <-> TCP ---

    private fun bridgeTcp(
        clientIn: InputStream, clientOut: OutputStream,
        remoteIn: InputStream, remoteOut: OutputStream,
        label: String, clientSocket: Socket, remoteSocket: Socket
    ) {
        val done = AtomicBoolean(false)

        val t1 = Thread({
            try {
                pipe(clientIn, remoteOut, isUp = true)
            } catch (_: Exception) {
            } finally {
                done.set(true)
                try { remoteSocket.close() } catch (_: Exception) {}
                try { clientSocket.close() } catch (_: Exception) {}
            }
        }, "tcp-c2r-$label")

        val t2 = Thread({
            try {
                pipe(remoteIn, clientOut, isUp = false)
            } catch (_: Exception) {
            } finally {
                done.set(true)
                try { clientSocket.close() } catch (_: Exception) {}
                try { remoteSocket.close() } catch (_: Exception) {}
            }
        }, "tcp-r2c-$label")

        t1.start()
        t2.start()
        t1.join()
        t2.join()
    }

    private fun pipe(src: InputStream, dst: OutputStream, isUp: Boolean) {
        val buf = ByteArray(65536)
        while (true) {
            val n = src.read(buf)
            if (n == -1) break
            if (isUp) stats.bytesUp.addAndGet(n.toLong())
            else stats.bytesDown.addAndGet(n.toLong())
            dst.write(buf, 0, n)
            dst.flush()
        }
    }

    // --- Bidirectional TCP <-> WebSocket ---

    private fun bridgeWs(
        clientIn: InputStream, clientOut: OutputStream,
        ws: RawWebSocket, label: String, clientSocket: Socket,
        dc: Int, dst: String, port: Int, isMedia: Boolean,
        splitter: MsgSplitter?
    ) {
        val dcTag = "DC$dc${if (isMedia) "m" else ""}"
        val startTime = System.currentTimeMillis()
        var upBytes = 0L
        var downBytes = 0L

        val t1 = Thread({
            try {
                val buf = ByteArray(65536)
                while (true) {
                    val n = clientIn.read(buf)
                    if (n == -1) {
                        splitter?.flush()?.firstOrNull()?.let { ws.send(it) }
                        break
                    }
                    val chunk = buf.copyOfRange(0, n)
                    stats.bytesUp.addAndGet(n.toLong())
                    upBytes += n

                    if (splitter != null) {
                        val parts = splitter.split(chunk)
                        if (parts.isEmpty()) continue
                        if (parts.size > 1) ws.sendBatch(parts) else ws.send(parts[0])
                    } else {
                        ws.send(chunk)
                    }
                }
            } catch (_: Exception) {
            } finally {
                try { ws.close() } catch (_: Exception) {}
                try { clientSocket.close() } catch (_: Exception) {}
            }
        }, "ws-c2s-$label")

        val t2 = Thread({
            try {
                while (true) {
                    val data = ws.recv() ?: break
                    stats.bytesDown.addAndGet(data.size.toLong())
                    downBytes += data.size
                    clientOut.write(data)
                    clientOut.flush()
                }
            } catch (_: Exception) {
            } finally {
                try { clientSocket.close() } catch (_: Exception) {}
                try { ws.close() } catch (_: Exception) {}
            }
        }, "ws-s2c-$label")

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        val elapsed = (System.currentTimeMillis() - startTime) / 1000.0
        log("[$label] $dcTag ($dst:$port) WS closed: ^${Stats.humanBytes(upBytes)} v${Stats.humanBytes(downBytes)} in %.1fs".format(elapsed))
    }

    private fun readExactly(input: InputStream, n: Int): ByteArray {
        val buf = ByteArray(n)
        var offset = 0
        while (offset < n) {
            val read = input.read(buf, offset, n - offset)
            if (read == -1) throw java.io.EOFException("Connection closed reading $n bytes at offset $offset")
            offset += read
        }
        return buf
    }
}
