package org.flowseal.tgwsproxy.proxy

import java.io.InputStream

/** One native MTProto packet from the client, without its transport framing and padding. */
internal class CfH2NativePacket(val body: ByteArray, val quick: Boolean)

/**
 * The client's MTProto transport framing (abridged, intermediate, padded intermediate) around
 * the bare packets that travel as HTTP bodies (upstream cf_h2._read_packet and _encode_reply).
 */
internal object CfH2Framing {

    /**
     * Reads one packet. [decrypt] is the client's decrypting keystream. Throws EOFException at the
     * end of the client stream and [CfH2ValueError] for a packet the HTTP endpoint cannot take.
     */
    fun readPacket(
        input: InputStream,
        decrypt: (ByteArray) -> ByteArray,
        tag: ByteArray,
        maxPacket: Int = CfH2Tuning.MAX_PACKET,
        maxPlainPadding: Int = CfH2Tuning.MAX_PLAIN_PADDING,
    ): CfH2NativePacket {
        fun plaintext(count: Int): ByteArray = decrypt(input.readExactly(count))

        val quick: Boolean
        val length: Long
        if (tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED)) {
            val first = plaintext(1)[0].toInt() and 0xFF
            quick = (first and 0x80) != 0
            var words = (first and 0x7F).toLong()
            if (words == 0x7FL) {
                val b = plaintext(3)
                words = (b[0].toLong() and 0xFF) or ((b[1].toLong() and 0xFF) shl 8) or
                    ((b[2].toLong() and 0xFF) shl 16)
            }
            length = words * 4
        } else {
            val value = Bytes.u32le(plaintext(4), 0)
            quick = (value and 0x80000000L) != 0L
            length = value and 0x7FFFFFFFL
        }
        val secure = tag.contentEquals(MtConst.PROTO_TAG_SECURE)
        if (length < 24 || length > maxPacket + (if (secure) maxPlainPadding else 0)) {
            throw CfH2ValueError("native packet length outside supported range: $length")
        }
        var body = plaintext(length.toInt())
        if (secure) {
            val packetLength: Long
            val maxPadding: Int
            if (isZero8(body)) {
                // Plaintext (auth key negotiation): message_data_length says where padding starts.
                packetLength = 20 + Bytes.u32le(body, 16)
                maxPadding = maxPlainPadding
            } else {
                packetLength = 24 + ((length - 24) / 16) * 16
                maxPadding = 15
            }
            val padding = length - packetLength
            if (packetLength < 24 || packetLength > length || padding > maxPadding) {
                throw CfH2ValueError(
                    "invalid padded native packet: frame=$length packet=$packetLength " +
                        "padding=$padding limit=$maxPadding"
                )
            }
            body = body.copyOf(packetLength.toInt())
        }
        if (body.size % 4 != 0 || body.size > maxPacket) {
            throw CfH2ValueError("invalid native packet alignment or size")
        }
        return CfH2NativePacket(body, quick)
    }

    /** Frames an HTTP response body for the client; padded intermediate gets 0-3 random bytes. */
    fun encodeReply(body: ByteArray, tag: ByteArray, maxPacket: Int = CfH2Tuning.MAX_PACKET): ByteArray {
        if (body.isEmpty() || body.size % 4 != 0 || body.size > maxPacket) {
            throw CfH2ValueError("invalid HTTP MTProto response length: ${body.size}")
        }
        if (tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED)) {
            val words = body.size / 4
            val prefix = if (words < 0x7F) {
                byteArrayOf(words.toByte())
            } else {
                byteArrayOf(0x7F, words.toByte(), (words ushr 8).toByte(), (words ushr 16).toByte())
            }
            return prefix + body
        }
        val padding = if (tag.contentEquals(MtConst.PROTO_TAG_SECURE)) {
            Bytes.random((Bytes.random(1)[0].toInt() and 0xFF) % 4)
        } else {
            ByteArray(0)
        }
        val total = body.size + padding.size
        val out = ByteArray(4 + total)
        int32le(total, out, 0)
        System.arraycopy(body, 0, out, 4, body.size)
        System.arraycopy(padding, 0, out, 4 + body.size, padding.size)
        return out
    }

    fun isZero8(b: ByteArray): Boolean {
        if (b.size < 8) return false
        for (i in 0 until 8) if (b[i].toInt() != 0) return false
        return true
    }

    fun int32le(value: Int): ByteArray = ByteArray(4).also { int32le(value, it, 0) }

    private fun int32le(value: Int, out: ByteArray, off: Int) {
        out[off] = value.toByte()
        out[off + 1] = (value ushr 8).toByte()
        out[off + 2] = (value ushr 16).toByte()
        out[off + 3] = (value ushr 24).toByte()
    }
}
