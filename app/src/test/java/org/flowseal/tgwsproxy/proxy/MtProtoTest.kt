package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** A Telegram client and a Telegram server, simulated, on both sides of the proxy's crypto. */
class MtProtoTest {

    private val secret = Bytes.fromHex("0123456789abcdef0123456789abcdef")

    /** What a client builds for an MTProto proxy with [secret] (as tdesktop does). */
    private class Client(secret: ByteArray, tag: ByteArray, dcIdx: Int) {
        val init: ByteArray
        val enc: AesCtr
        val dec: AesCtr

        init {
            val rnd = Bytes.random(64)
            System.arraycopy(tag, 0, rnd, 56, 4)
            rnd[60] = (dcIdx and 0xFF).toByte()
            rnd[61] = ((dcIdx shr 8) and 0xFF).toByte()
            val encKey = Bytes.sha256(rnd.copyOfRange(8, 40), secret)
            val encIv = rnd.copyOfRange(40, 56)
            enc = AesCtr(encKey, encIv)
            val encrypted = enc.update(rnd)
            init = rnd.copyOf()
            System.arraycopy(encrypted, 56, init, 56, 8)
            val rev = Bytes.reversed(rnd.copyOfRange(8, 56))
            dec = AesCtr(Bytes.sha256(rev.copyOfRange(0, 32), secret), rev.copyOfRange(32, 48))
        }
    }

    @Test
    fun handshakeReadsDcAndTag() {
        for ((tag, dcIdx) in listOf(
            MtConst.PROTO_TAG_ABRIDGED to 2,
            MtConst.PROTO_TAG_INTERMEDIATE to -4,
            MtConst.PROTO_TAG_SECURE to 10003,
        )) {
            val c = Client(secret, tag, dcIdx)
            val hs = MtProto.tryHandshake(c.init, secret)
            assertNotNull(hs)
            assertEquals(kotlin.math.abs(dcIdx), hs!!.dc)
            assertEquals(dcIdx < 0, hs.isMedia)
            assertArrayEquals(tag, hs.protoTag)
        }
    }

    @Test
    fun wrongSecretIsRejected() {
        val c = Client(secret, MtConst.PROTO_TAG_SECURE, 2)
        assertNull(MtProto.tryHandshake(c.init, Bytes.fromHex("ffffffffffffffffffffffffffffffff")))
    }

    @Test
    fun relayInitAvoidsReservedPrefixesAndCarriesDc() {
        repeat(200) {
            val init = MtProto.generateRelayInit(MtConst.PROTO_TAG_SECURE, -2)
            assertFalse((init[0].toInt() and 0xFF) == 0xEF)
            assertFalse(MtConst.RESERVED_STARTS.any { Bytes.startsWith(init, it) })
            assertFalse(Bytes.startsWith(init, ByteArray(4), 4))
            // Telegram decrypts it with the raw key from the init itself
            val plain = AesCtr(init.copyOfRange(8, 40), init.copyOfRange(40, 56)).update(init)
            assertArrayEquals(MtConst.PROTO_TAG_SECURE, plain.copyOfRange(56, 60))
            assertEquals(-2, ((plain[60].toInt() and 0xFF) or (plain[61].toInt() shl 8)).toShort().toInt())
        }
    }

    @Test
    fun reencryptionRoundTrip() {
        val c = Client(secret, MtConst.PROTO_TAG_INTERMEDIATE, 2)
        val hs = MtProto.tryHandshake(c.init, secret)!!
        val relayInit = MtProto.generateRelayInit(hs.protoTag, 2)
        val ctx = MtProto.buildCryptoCtx(hs.prekeyAndIv, secret, relayInit)

        // Telegram's side of the relay connection
        val tgDec = AesCtr(relayInit.copyOfRange(8, 40), relayInit.copyOfRange(40, 56))
        tgDec.update(MtConst.ZERO_64)
        val rev = Bytes.reversed(relayInit.copyOfRange(8, 56))
        val tgEnc = AesCtr(rev.copyOfRange(0, 32), rev.copyOfRange(32, 48))

        for (size in listOf(1, 17, 4096, 70000)) {
            val up = Bytes.random(size)
            val onWire = c.enc.update(up)
            val toTelegram = ctx.tgEnc.update(ctx.cltDec.update(onWire))
            assertArrayEquals(up, tgDec.update(toTelegram))

            val down = Bytes.random(size)
            val fromTelegram = tgEnc.update(down)
            val toClient = ctx.cltEnc.update(ctx.tgDec.update(fromTelegram))
            assertArrayEquals(down, c.dec.update(toClient))
        }
    }

    @Test
    fun splitterCutsIntermediatePackets() {
        val s = MsgSplitter(MtConst.PROTO_INTERMEDIATE_INT)
        fun packet(n: Int): ByteArray {
            val p = ByteArray(4 + n)
            p[0] = n.toByte(); p[1] = (n shr 8).toByte()
            return p
        }
        val a = packet(8)
        val b = packet(300)
        val stream = a + b
        // cipher == plain here; the splitter cuts by the plain lengths
        val first = s.split(stream.copyOfRange(0, 20), stream.copyOfRange(0, 20))
        assertEquals(1, first.size)
        assertArrayEquals(a, first[0])
        val rest = s.split(stream.copyOfRange(20, stream.size), stream.copyOfRange(20, stream.size))
        assertEquals(1, rest.size)
        assertArrayEquals(b, rest[0])
        assertTrue(s.flush().isEmpty())
    }

    @Test
    fun splitterCutsAbridgedPackets() {
        val s = MsgSplitter(MtConst.PROTO_ABRIDGED_INT)
        val small = byteArrayOf(2) + ByteArray(8)
        val big = byteArrayOf(0x7F, 0x00, 0x01, 0x00) + ByteArray(256 * 4)
        val stream = small + big
        val parts = s.split(stream, stream)
        assertEquals(2, parts.size)
        assertArrayEquals(small, parts[0])
        assertArrayEquals(big, parts[1])
    }

    @Test
    fun censorKeepsTelegramAndMasksOthers() {
        assertEquals("kws2.web.telegram.org", ProxyLog.censor("kws2.web.telegram.org"))
        assertEquals("via exa****.com now", ProxyLog.censor("via example.com now"))
        assertEquals("proxy.log", ProxyLog.censor("proxy.log"))
        assertEquals("javax.net.ssl.SSLException: x", ProxyLog.censor("javax.net.ssl.SSLException: x"))
    }

    @Test
    fun hostCheckWildcards() {
        assertTrue(HostCheck.nameMatches("*.web.telegram.org", "kws2.web.telegram.org"))
        assertTrue(HostCheck.nameMatches("*.web.telegram.org", "KWS2-1.web.telegram.org"))
        assertFalse(HostCheck.nameMatches("*.web.telegram.org", "a.kws2.web.telegram.org"))
        assertFalse(HostCheck.nameMatches("*.web.telegram.org", "web.telegram.org"))
        assertTrue(HostCheck.nameMatches("web.telegram.org", "web.telegram.org"))
        assertFalse(HostCheck.nameMatches("*.com", "example.com"))
    }

    @Test
    fun settingsLinksAndParsing() {
        val s = ProxySettings(secretHex = "00112233445566778899aabbccddeeff")
        assertEquals("tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff", s.proxyLink())
        val ee = s.copy(fakeTlsDomain = "ab.c")
        assertEquals("tg://proxy?server=127.0.0.1&port=1443&secret=ee00112233445566778899aabbccddeeff61622e63", ee.proxyLink())
        assertEquals(mapOf(2 to "1.2.3.4"), ProxySettings.parseDcIpList(listOf(" 2:1.2.3.4 ", "")))
        assertEquals(listOf("a.com", "b.org"), ProxySettings.coerceDomainList("a.com, A.com;b.org\n"))
        assertTrue(ProxySettings.isValidSecret("00112233445566778899aabbccddeeff"))
        assertFalse(ProxySettings.isValidSecret("0011"))
    }
}
