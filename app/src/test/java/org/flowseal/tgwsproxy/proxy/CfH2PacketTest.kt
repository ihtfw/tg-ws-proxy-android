package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.InputStream

/** Native MTProto transport framing (upstream tests/test_cf_h2.py NativeFramingTest). */
class CfH2PacketTest {

    private val identity: (ByteArray) -> ByteArray = { it }

    /** Delivers the wire one byte per read(), like a fragmented TCP stream. */
    private class Trickle(private val data: ByteArray) : InputStream() {
        private var pos = 0
        override fun read(): Int = if (pos < data.size) data[pos++].toInt() and 0xFF else -1
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (pos >= data.size) return -1
            b[off] = data[pos++]
            return 1
        }
    }

    private fun packet(wire: ByteArray, tag: ByteArray, maxPacket: Int = CfH2Tuning.MAX_PACKET) =
        CfH2Framing.readPacket(Trickle(wire), identity, tag, maxPacket)

    private fun plainBody(declared: Int, payload: Int): ByteArray =
        cat(ByteArray(8), rep('m', 8), CfH2Framing.int32le(declared), rep('p', payload))

    private fun assertValueError(contains: String? = null, block: () -> Unit) {
        try {
            block()
            fail("expected CfH2ValueError")
        } catch (e: CfH2ValueError) {
            if (contains != null) assertTrue(e.message, e.message!!.contains(contains))
        }
    }

    @Test
    fun fragmentedAbridgedExtendedAndQuickAck() {
        val body = rep('a', 512)
        val decoded = packet(cat(byteArrayOf(0xFF.toByte(), 0x80.toByte(), 0, 0), body), MtConst.PROTO_TAG_ABRIDGED)
        assertArrayEquals(body, decoded.body)
        assertTrue(decoded.quick)
    }

    @Test
    fun intermediateQuickAckDoesNotChangeBody() {
        val body = rep('a', 40)
        val decoded = packet(cat(CfH2Framing.int32le(body.size or Int.MIN_VALUE), body), MtConst.PROTO_TAG_INTERMEDIATE)
        assertArrayEquals(body, decoded.body)
        assertTrue(decoded.quick)
    }

    @Test
    fun paddedPlaintextRemovesAllFifteenPaddingLengths() {
        val body = plainBody(20, 20)
        for (padding in 0 until 16) {
            val wire = body + rep('z', padding)
            val decoded = packet(cat(CfH2Framing.int32le(wire.size), wire), MtConst.PROTO_TAG_SECURE)
            assertArrayEquals("padding=$padding", body, decoded.body)
            assertFalse(decoded.quick)
        }
    }

    @Test
    fun plaintextAcceptsExtendedPaddingUsedByAppleAndAndroid() {
        // MTProtoKit appends 0..236 bytes outside message_data_length, then the TCP transport adds
        // 0..15 more. Android uses 0..256 directly.
        val body = plainBody(20, 20)
        for (padding in 0..256) {
            val wire = body + rep('z', padding)
            val decoded = CfH2Framing.readPacket(
                ByteArrayInputStream(cat(CfH2Framing.int32le(wire.size or Int.MIN_VALUE), wire)),
                identity, MtConst.PROTO_TAG_SECURE,
            )
            assertArrayEquals("padding=$padding", body, decoded.body)
            assertTrue(decoded.quick)
        }
    }

    @Test
    fun paddedPlaintextPreservesPaddingIncludedInMessageLength() {
        val body = cat(ByteArray(8), rep('m', 8), CfH2Framing.int32le(272), rep('p', 20), rep('d', 252))
        val decoded = packet(cat(CfH2Framing.int32le(body.size + 15), body, rep('z', 15)), MtConst.PROTO_TAG_SECURE)
        assertArrayEquals(body, decoded.body)
    }

    @Test
    fun extendedPaddingPreservesPacketSizeLimit() {
        val body = plainBody(20, 20)
        val wire = body + rep('z', 256)
        assertArrayEquals(body, packet(cat(CfH2Framing.int32le(wire.size), wire), MtConst.PROTO_TAG_SECURE, body.size).body)
        val oversized = cat(body.copyOf(16), CfH2Framing.int32le(24), rep('p', 24))
        assertValueError("size") {
            packet(cat(CfH2Framing.int32le(oversized.size), oversized), MtConst.PROTO_TAG_SECURE, body.size)
        }
        val encrypted = cat(rep('k', 8), rep('m', 16), rep('c', 32))
        assertValueError("size") {
            packet(cat(CfH2Framing.int32le(encrypted.size), encrypted), MtConst.PROTO_TAG_SECURE, body.size)
        }
    }

    @Test
    fun invalidPlaintextLengthsAndExcessPaddingAreRejected() {
        for ((declared, payload, padding) in listOf(
            Triple(0, 20, 0), Triple(24, 20, 0), Triple(21, 21, 0), Triple(20, 20, 257), Triple(-1, 20, 0),
        )) {
            val wire = plainBody(declared, payload) + rep('z', padding)
            assertValueError {
                packet(cat(CfH2Framing.int32le(wire.size), wire), MtConst.PROTO_TAG_SECURE)
            }
        }
    }

    @Test
    fun paddedCiphertextRemovesFullPaddingBlocks() {
        val body = cat(rep('k', 8), rep('m', 16), rep('c', 32))
        for (padding in 0 until 16) {
            val wire = body + rep('z', padding)
            assertArrayEquals("padding=$padding", body, packet(cat(CfH2Framing.int32le(wire.size), wire), MtConst.PROTO_TAG_SECURE).body)
        }
    }

    @Test
    fun oversizeHeaderRejectedBeforeBodyRead() {
        // Only the length is available: reading the body would hit EOF instead.
        assertValueError("length") {
            CfH2Framing.readPacket(
                ByteArrayInputStream(CfH2Framing.int32le(CfH2Tuning.MAX_PACKET + 4)),
                identity, MtConst.PROTO_TAG_INTERMEDIATE,
            )
        }
    }

    @Test
    fun negativeTransportErrorKeepsNativeFraming() {
        val error = CfH2Framing.int32le(-404)
        assertArrayEquals(cat(byteArrayOf(1), error), CfH2Framing.encodeReply(error, MtConst.PROTO_TAG_ABRIDGED))
        assertArrayEquals(cat(byteArrayOf(4, 0, 0, 0), error), CfH2Framing.encodeReply(error, MtConst.PROTO_TAG_INTERMEDIATE))
        val secure = CfH2Framing.encodeReply(error, MtConst.PROTO_TAG_SECURE)
        val length = Bytes.u32le(secure, 0).toInt()
        assertEquals(secure.size - 4, length)
        assertTrue(length in 4..7)
        assertArrayEquals(error, secure.copyOfRange(4, 8))
    }

    @Test
    fun abridgedReplyUsesExtendedLengthFromOneHundredTwentySevenWords() {
        val small = rep('s', 126 * 4)
        assertEquals(126, CfH2Framing.encodeReply(small, MtConst.PROTO_TAG_ABRIDGED)[0].toInt())
        val large = rep('l', 128 * 1024)
        val framed = CfH2Framing.encodeReply(large, MtConst.PROTO_TAG_ABRIDGED)
        assertArrayEquals(byteArrayOf(0x7F, 0, 0x80.toByte(), 0), framed.copyOf(4))
        assertArrayEquals(large, framed.copyOfRange(4, framed.size))
    }

    @Test
    fun repliesThatAreEmptyOrMisalignedAreRejected() {
        for (bad in listOf(ByteArray(0), rep('x', 41))) {
            assertValueError("response length") { CfH2Framing.encodeReply(bad, MtConst.PROTO_TAG_INTERMEDIATE) }
        }
    }
}
