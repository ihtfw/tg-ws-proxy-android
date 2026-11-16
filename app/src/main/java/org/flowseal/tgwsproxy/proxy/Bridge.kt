package org.flowseal.tgwsproxy.proxy

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap

/** One accepted client, past the 64-byte init: its streams, keys and how to close it. */
class ClientConn(
    val input: InputStream,
    val output: OutputStream,
    val label: String,
    val crypto: CryptoCtx,
    private val closeAction: () -> Unit,
) {
    fun close() = try {
        closeAction()
    } catch (_: Throwable) {
    }
}

/**
 * Moving bytes between the client and Telegram, re-encrypted, and the fallbacks for a DC whose
 * pooled WebSocket is not available (upstream proxy/bridge.py).
 */
class Bridge(
    private val ctx: ProxyContext,
    private val cfWorkerPool: CfWorkerPool? = null,
    private val h2Pool: CfH2Pool? = null,
) {

    companion object {
        const val TCP_BACKOFF_INITIAL_MS = 30_000L
        const val TCP_BACKOFF_MAX_MS = 3_600_000L
        private const val READ_CHUNK = 65536
    }

    private val tcpFailures = ConcurrentHashMap<String, Int>()
    private val tcpRetryAfter = ConcurrentHashMap<String, Long>()
    private val tcpConnecting = ConcurrentHashMap.newKeySet<String>()

    private val stats get() = ctx.stats
    private fun now() = System.nanoTime() / 1_000_000

    /** Tries each fallback in turn; false when none could take the client. */
    fun doFallback(
        client: ClientConn,
        relayInit: ByteArray,
        dc: Int,
        isTestDc: Boolean,
        isMedia: Boolean,
        splitter: MsgSplitter?,
        protoTag: ByteArray,
    ): Boolean {
        val ipTable = if (isTestDc) MtConst.DC_TEST_IPS else MtConst.DC_DEFAULT_IPS
        val fallbackDst = ipTable[dc]
        val useCf = ctx.settings.fallbackCfproxy && !isTestDc
        val workerDomains = ctx.settings.cfproxyWorkerDomains

        val methods = ArrayList<String>()
        if (workerDomains.isNotEmpty() && fallbackDst != null) methods.add("cf_worker")
        if (useCf) methods.add("cf")
        if (fallbackDst != null) methods.add("tcp")

        for (method in methods) {
            when (method) {
                "cf_worker" -> if (cfWorkerFallback(client, relayInit, dc, isTestDc, isMedia, fallbackDst!!)) return true
                "cf" -> {
                    if (isMedia && h2Pool != null) {
                        val channel = h2Pool.open(dc, client.label)
                        if (channel != null) {
                            stats.connectionsH2.incrementAndGet()
                            stats.connectionsCfproxy.incrementAndGet()
                            bridgeH2(ctx, client.input, client.output, channel, client.crypto, protoTag, client.label)
                            return true
                        }
                    }
                    if (cfproxyFallback(client, relayInit, dc, isMedia, splitter)) return true
                }
                "tcp" -> if (tcpFallback(client, fallbackDst!!, 443, relayInit)) return true
            }
        }
        return false
    }

    /** The user's Cloudflare Worker, which opens the WebSocket to [fallbackDst] for us. */
    private fun cfWorkerFallback(
        client: ClientConn, relayInit: ByteArray, dc: Int, isTestDc: Boolean, isMedia: Boolean, fallbackDst: String,
    ): Boolean {
        val workerDomains = ctx.settings.cfproxyWorkerDomains
        if (workerDomains.isEmpty()) return false
        val mediaTag = if (isMedia) " media" else ""
        val pool = cfWorkerPool
        val pooled = if (isTestDc || pool == null) null else pool.get(dc, fallbackDst, workerDomains)
        var ws: RawWebSocket? = null
        if (pooled != null) {
            ws = pooled.first
            ProxyLog.i("[${client.label}] DC$dc$mediaTag -> CF worker pool hit via ${pooled.second} for $fallbackDst")
        } else {
            val path = CfWorkerPool.workerPath(fallbackDst, dc)
            for (domain in pool?.availableDomains(workerDomains) ?: workerDomains.distinct().shuffled()) {
                ProxyLog.i("[${client.label}] DC$dc$mediaTag -> trying CF worker $domain for $fallbackDst")
                try {
                    ws = RawWebSocket.connect(domain, domain, timeoutMs = 10_000, path = path, secure = !ctx.settings.disableSecure)
                    break
                } catch (e: Exception) {
                    ProxyLog.w("[${client.label}] DC$dc$mediaTag CF worker $domain failed: ${errStr(e)}")
                }
            }
        }
        val socket = ws ?: return false
        stats.connectionsCfproxy.incrementAndGet()
        socket.send(relayInit)
        bridgeWsReencrypt(client, socket, dc, isMedia, null)
        return true
    }

    /** A WebSocket to kws<dc>.<domain>, a domain proxied by Cloudflare to Telegram. */
    private fun cfproxyFallback(
        client: ClientConn, relayInit: ByteArray, dc: Int, isMedia: Boolean, splitter: MsgSplitter?,
    ): Boolean {
        val mediaTag = if (isMedia) " media" else ""
        ProxyLog.i("[${client.label}] DC$dc$mediaTag -> trying CF proxy")
        val started = now()
        var ws: RawWebSocket? = null
        var chosen: String? = null
        for (base in ctx.balancer.domainsForDc(dc)) {
            val domain = "kws$dc.$base"
            try {
                ws = RawWebSocket.connect(domain, domain, timeoutMs = 10_000, secure = !ctx.settings.disableSecure)
                chosen = base
                break
            } catch (e: Exception) {
                ProxyLog.w("[${client.label}] DC$dc$mediaTag CF proxy failed: ${errStr(e)}")
            }
        }
        val socket = ws ?: return false
        ProxyLog.d { "[${client.label}] WS CONNECT DC$dc$mediaTag route=cf setup_ms=${now() - started}" }
        if (chosen != null && ctx.balancer.updateDomainForDc(dc, chosen)) {
            ProxyLog.i("[${client.label}] Switched active CF domain")
        }
        stats.connectionsCfproxy.incrementAndGet()
        socket.send(relayInit)
        bridgeWsReencrypt(client, socket, dc, isMedia, splitter)
        return true
    }

    private fun tcpFallback(client: ClientConn, dst: String, port: Int, relayInit: ByteArray): Boolean {
        val key = "$dst:$port"
        if (key in tcpConnecting || now() < (tcpRetryAfter[key] ?: 0)) {
            ProxyLog.d { "[${client.label}] TCP fallback to $key skipped (backoff or connecting)" }
            return false
        }
        tcpConnecting.add(key)
        val remote = Socket()
        try {
            try {
                ProxyLog.i("[${client.label}] TCP fallback to $key")
                remote.tcpNoDelay = true
                remote.connect(InetSocketAddress(dst, port), 10_000)
                remote.getOutputStream().apply { write(relayInit); flush() }
            } catch (e: Exception) {
                remote.closeQuietly()
                val failures = (tcpFailures[key] ?: 0) + 1
                tcpFailures[key] = failures
                val delay = minOf(TCP_BACKOFF_INITIAL_MS shl minOf(failures - 1, 7), TCP_BACKOFF_MAX_MS)
                tcpRetryAfter[key] = now() + delay
                ProxyLog.w("[${client.label}] TCP fallback to $key failed: ${errStr(e)}; retry in ${delay / 1000}s")
                return false
            } finally {
                tcpConnecting.remove(key)
            }
            tcpFailures.remove(key)
            tcpRetryAfter.remove(key)
            stats.connectionsTcpFallback.incrementAndGet()
            bridgeTcpReencrypt(client, remote)
            return true
        } finally {
            remote.closeQuietly()
        }
    }

    /**
     * Client TCP <-> Telegram WebSocket. Client ciphertext is decrypted with the client's key and
     * encrypted with the relay key; [splitter] cuts the upload into whole MTProto packets.
     * Blocks until either side ends, then closes both.
     */
    fun bridgeWsReencrypt(
        client: ClientConn,
        ws: RawWebSocket,
        dc: Int?,
        isMedia: Boolean,
        splitter: MsgSplitter?,
    ) {
        val tag = if (dc != null) dcTag(dc, isMedia) else "DC?"
        val crypto = client.crypto
        val start = now()
        val reason = java.util.concurrent.atomic.AtomicReference("normal")
        fun closeReason(r: String) { reason.compareAndSet("normal", r) }
        var upBytes = 0L
        var upPackets = 0
        var downBytes = 0L
        var downPackets = 0

        val upload = Runnable {
            try {
                val buf = ByteArray(READ_CHUNK)
                while (true) {
                    val n = client.input.read(buf)
                    if (n < 0) {
                        splitter?.flush()?.firstOrNull()?.let { ws.send(it) }
                        closeReason("client: eof")
                        break
                    }
                    if (n == 0) continue
                    stats.bytesUp.addAndGet(n.toLong())
                    upBytes += n
                    upPackets++
                    val plain = crypto.cltDec.update(buf, 0, n)
                    val chunk = crypto.tgEnc.update(plain)
                    if (splitter != null) {
                        val parts = splitter.split(chunk, plain)
                        if (parts.isEmpty()) continue
                        if (parts.size > 1) ws.sendBatch(parts) else ws.send(parts[0])
                    } else {
                        ws.send(chunk)
                    }
                }
            } catch (e: IOException) {
                closeReason("client: ${e.javaClass.simpleName}")
            } catch (e: Exception) {
                closeReason("client: ${e.javaClass.simpleName}: ${e.message}")
                ProxyLog.d { "[${client.label}] tcp->ws ended: ${errStr(e)}" }
            } finally {
                ws.closeQuietly()
                client.close()
            }
        }

        val uploadThread = Thread(upload, "up-${client.label}").apply { isDaemon = true; start() }
        try {
            while (true) {
                val data = ws.recv()
                if (data == null) {
                    closeReason("upstream: ws_close")
                    break
                }
                val n = data.size
                stats.bytesDown.addAndGet(n.toLong())
                downBytes += n
                downPackets++
                val out = crypto.cltEnc.update(crypto.tgDec.update(data))
                client.output.write(out)
                client.output.flush()
            }
        } catch (e: IOException) {
            closeReason("upstream: ${e.javaClass.simpleName}")
        } catch (e: Exception) {
            closeReason("upstream: ${e.javaClass.simpleName}: ${e.message}")
            ProxyLog.d { "[${client.label}] ws->tcp ended: ${errStr(e)}" }
        } finally {
            ws.closeQuietly()
            client.close()
            try {
                uploadThread.join(2_000)
            } catch (_: InterruptedException) {
            }
            val elapsed = (now() - start) / 1000.0
            ProxyLog.i(
                "[${client.label}] $tag WS session closed (${reason.get()}): " +
                    "^${humanBytes(upBytes)} ($upPackets pkts) v${humanBytes(downBytes)} ($downPackets pkts) " +
                    "in ${String.format(java.util.Locale.US, "%.1f", elapsed)}s"
            )
        }
    }

    /** Client TCP <-> Telegram TCP, re-encrypted both ways. Blocks until either side ends. */
    fun bridgeTcpReencrypt(client: ClientConn, remote: Socket) {
        val crypto = client.crypto
        val remoteIn = remote.getInputStream()
        val remoteOut = remote.getOutputStream()
        val upload = Thread({
            try {
                val buf = ByteArray(READ_CHUNK)
                while (true) {
                    val n = client.input.read(buf)
                    if (n < 0) break
                    stats.bytesUp.addAndGet(n.toLong())
                    remoteOut.write(crypto.tgEnc.update(crypto.cltDec.update(buf, 0, n)))
                    remoteOut.flush()
                }
            } catch (e: Exception) {
                ProxyLog.d { "[${client.label}] forward ended: ${errStr(e)}" }
            } finally {
                remote.closeQuietly()
                client.close()
            }
        }, "tcp-up-${client.label}").apply { isDaemon = true; start() }
        try {
            val buf = ByteArray(READ_CHUNK)
            while (true) {
                val n = remoteIn.read(buf)
                if (n < 0) break
                stats.bytesDown.addAndGet(n.toLong())
                client.output.write(crypto.cltEnc.update(crypto.tgDec.update(buf, 0, n)))
                client.output.flush()
            }
        } catch (e: Exception) {
            ProxyLog.d { "[${client.label}] forward ended: ${errStr(e)}" }
        } finally {
            remote.closeQuietly()
            client.close()
            try {
                upload.join(2_000)
            } catch (_: InterruptedException) {
            }
        }
    }
}
