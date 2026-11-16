package org.flowseal.tgwsproxy.proxy

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket

/**
 * Talks to Telegram through the proxy: an MTProto proxy client sends req_pq_multi and expects
 * resPQ with its nonce back. Needs the network, so it runs only with TGWS_LIVE=1:
 * `TGWS_LIVE=1 gradle :app:testDebugUnitTest --tests '*LiveProxyTest*'`.
 */
class LiveProxyTest {

    private var server: ProxyServer? = null
    private val lines = java.util.Collections.synchronizedList(ArrayList<String>())

    @Before
    fun live() {
        assumeTrue(System.getenv("TGWS_LIVE") == "1")
        ProxyLog.verbose = true
        ProxyLog.sink = { level, msg -> lines.add("$level $msg"); println("${level.name.padEnd(5)} $msg") }
    }

    @After
    fun stop() {
        server?.stop()
    }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    private fun startProxy(settings: ProxySettings): ProxySettings {
        val s = settings.copy(port = freePort())
        server = ProxyServer(s).also { it.start() }
        return s
    }

    /** Opens a proxied connection to [dcIdx] and checks Telegram's resPQ. */
    private fun roundTrip(s: ProxySettings, dcIdx: Int, tag: ByteArray = MtConst.PROTO_TAG_INTERMEDIATE) {
        val secret = s.secret
        val rnd = Bytes.random(64)
        while ((rnd[0].toInt() and 0xFF) == 0xEF) rnd[0] = 0
        System.arraycopy(tag, 0, rnd, 56, 4)
        rnd[60] = (dcIdx and 0xFF).toByte()
        rnd[61] = ((dcIdx shr 8) and 0xFF).toByte()
        val enc = AesCtr(Bytes.sha256(rnd.copyOfRange(8, 40), secret), rnd.copyOfRange(40, 56))
        val encInit = enc.update(rnd)
        val init = rnd.copyOf()
        System.arraycopy(encInit, 56, init, 56, 8)
        val rev = Bytes.reversed(rnd.copyOfRange(8, 56))
        val dec = AesCtr(Bytes.sha256(rev.copyOfRange(0, 32), secret), rev.copyOfRange(32, 48))

        // req_pq_multi#be7e8ef1 nonce:int128, as an unencrypted message
        val nonce = Bytes.random(16)
        val msgId = (System.currentTimeMillis() / 1000) shl 32
        val msg = java.nio.ByteBuffer.allocate(40).order(java.nio.ByteOrder.LITTLE_ENDIAN)
            .putLong(0).putLong(msgId).putInt(20).putInt(0xbe7e8ef1.toInt()).put(nonce).array()
        val packet = java.nio.ByteBuffer.allocate(4 + msg.size + (if (tag.contentEquals(MtConst.PROTO_TAG_SECURE)) 4 else 0))
            .order(java.nio.ByteOrder.LITTLE_ENDIAN)
        if (tag.contentEquals(MtConst.PROTO_TAG_SECURE)) {
            packet.putInt(msg.size + 4).put(msg).put(Bytes.random(4))
        } else {
            packet.putInt(msg.size).put(msg)
        }

        Socket().use { sock ->
            sock.connect(InetSocketAddress("127.0.0.1", s.port), 5000)
            sock.soTimeout = 20_000
            val out = sock.getOutputStream()
            out.write(init)
            out.write(enc.update(packet.array()))
            out.flush()
            val input: InputStream = sock.getInputStream()
            val lenBytes = dec.update(input.readExactly(4))
            val len = (Bytes.u32le(lenBytes, 0) and 0x7FFFFFFF).toInt()
            val body = dec.update(input.readExactly(len))
            // auth_key_id(8) msg_id(8) length(4) then resPQ#05162463 nonce
            val ctor = Bytes.u32le(body, 20).toInt()
            assertEquals("resPQ constructor", 0x05162463, ctor)
            assertArrayEquals("nonce echoed", nonce, body.copyOfRange(24, 40))
        }
    }

    @Test
    fun throughWebSocketPool() {
        val s = startProxy(ProxySettings(fallbackCfproxy = false))
        Thread.sleep(4000) // pool warmup
        roundTrip(s, 2)
        roundTrip(s, -4, MtConst.PROTO_TAG_SECURE)
        roundTrip(s, 4)
        assert(lines.any { "WS pool hit" in it })
    }

    @Test
    fun throughTcpFallback() {
        val s = startProxy(ProxySettings(dcRedirects = emptyMap(), fallbackCfproxy = false))
        roundTrip(s, 1)
        roundTrip(s, 5)
        assert(lines.any { "TCP fallback to" in it })
    }

    @Test
    fun throughCloudflareProxy() {
        // no DC:IP entries and no pool: every DC goes to the fallbacks, CF proxy before TCP
        val s = startProxy(ProxySettings(dcRedirects = emptyMap(), poolSize = 0, cfproxyH2Media = false))
        roundTrip(s, 2)
        roundTrip(s, 4)
        assert(lines.any { "trying CF proxy" in it })
        assert(lines.none { "TCP fallback to" in it }) { "fell through to TCP" }
        assertEquals(2L, server!!.stats.connectionsCfproxy.get())
    }

    @Test
    fun domainListFromGitHub() {
        val list = CfProxyDomains.normalize(CfProxyDomains.parseList(CfProxyDomains.fetch(CfProxyDomains.DOMAINS_URL)))
        assert(list.size >= 3) { "only ${list.size} domains" }
    }

    @Test
    fun wrongSecretIsCountedBad() {
        val s = startProxy(ProxySettings(fallbackCfproxy = false))
        val other = s.copy(secretHex = "ffffffffffffffffffffffffffffffff")
        try {
            roundTrip(other, 2)
        } catch (_: Exception) {
        }
        Thread.sleep(200)
        assertEquals(1L, server!!.stats.connectionsBad.get())
    }
}
