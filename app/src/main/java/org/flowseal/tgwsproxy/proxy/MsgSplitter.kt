package org.flowseal.tgwsproxy.proxy

/**
 * Splits the re-encrypted upload stream into whole MTProto transport packets, so each one goes
 * out as its own WebSocket frame (upstream bridge.MsgSplitter). Packet lengths are read from the
 * plaintext; the ciphertext is what is cut and sent.
 */
class MsgSplitter(private val proto: Int) {
    private var cipherBuf = ByteArray(0)
    private var plainBuf = ByteArray(0)
    private var disabled = false

    fun split(chunk: ByteArray, plain: ByteArray): List<ByteArray> {
        if (chunk.isEmpty()) return emptyList()
        if (disabled) return listOf(chunk)

        cipherBuf = if (cipherBuf.isEmpty()) chunk else cipherBuf + chunk
        plainBuf = if (plainBuf.isEmpty()) plain else plainBuf + plain

        val parts = ArrayList<ByteArray>()
        var offset = 0
        val bufLen = cipherBuf.size
        while (offset < bufLen) {
            val packetLen = nextPacketLen(offset, bufLen - offset) ?: break
            if (packetLen <= 0) {
                parts.add(if (offset == 0) cipherBuf else cipherBuf.copyOfRange(offset, bufLen))
                offset = bufLen
                disabled = true
                break
            }
            parts.add(
                if (offset == 0 && packetLen == bufLen) cipherBuf
                else cipherBuf.copyOfRange(offset, offset + packetLen)
            )
            offset += packetLen
        }
        if (offset > 0) {
            cipherBuf = if (offset >= cipherBuf.size) ByteArray(0) else cipherBuf.copyOfRange(offset, cipherBuf.size)
            plainBuf = if (offset >= plainBuf.size) ByteArray(0) else plainBuf.copyOfRange(offset, plainBuf.size)
        }
        return parts
    }

    fun flush(): List<ByteArray> {
        if (cipherBuf.isEmpty()) return emptyList()
        val tail = cipherBuf
        cipherBuf = ByteArray(0)
        plainBuf = ByteArray(0)
        return listOf(tail)
    }

    private fun nextPacketLen(offset: Int, avail: Int): Int? {
        if (avail <= 0) return null
        return when (proto) {
            MtConst.PROTO_ABRIDGED_INT -> nextAbridgedLen(offset, avail)
            MtConst.PROTO_INTERMEDIATE_INT, MtConst.PROTO_PADDED_INTERMEDIATE_INT -> nextIntermediateLen(offset, avail)
            else -> 0
        }
    }

    private fun nextAbridgedLen(offset: Int, avail: Int): Int? {
        val first = plainBuf[offset].toInt() and 0xFF
        val payloadLen: Long
        val headerLen: Int
        if (first == 0x7F || first == 0xFF) {
            if (avail < 4) return null
            payloadLen = ((plainBuf[offset + 1].toLong() and 0xFF) or
                ((plainBuf[offset + 2].toLong() and 0xFF) shl 8) or
                ((plainBuf[offset + 3].toLong() and 0xFF) shl 16)) * 4
            headerLen = 4
        } else {
            payloadLen = ((first and 0x7F) * 4).toLong()
            headerLen = 1
        }
        if (payloadLen <= 0) return 0
        val packetLen = headerLen + payloadLen
        if (packetLen > Int.MAX_VALUE) return 0
        if (avail < packetLen) return null
        return packetLen.toInt()
    }

    private fun nextIntermediateLen(offset: Int, avail: Int): Int? {
        if (avail < 4) return null
        val payloadLen = Bytes.u32le(plainBuf, offset) and 0x7FFFFFFF
        if (payloadLen <= 0) return 0
        val packetLen = 4 + payloadLen
        if (packetLen > Int.MAX_VALUE) return 0
        if (avail < packetLen) return null
        return packetLen.toInt()
    }
}
