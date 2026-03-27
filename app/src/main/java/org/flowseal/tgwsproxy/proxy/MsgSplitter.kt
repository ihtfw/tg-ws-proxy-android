package org.flowseal.tgwsproxy.proxy

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Splits client TCP data into individual MTProto transport packets.
 * Port of the Python _MsgSplitter class.
 *
 * Some mobile clients coalesce multiple MTProto packets into one TCP write,
 * and TCP reads may also cut a packet in half. Keeps a rolling buffer so
 * incomplete packets are not forwarded as standalone frames.
 */
class MsgSplitter(initData: ByteArray, private val proto: Int) {

    private val cipher: Cipher
    private val cipherBuf = ByteArrayOutputStream()
    private val plainBuf = ByteArrayOutputStream()
    private var disabled = false

    init {
        val key = initData.copyOfRange(8, 40)
        val iv = initData.copyOfRange(40, 56)
        cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        // Skip init packet (64 bytes)
        cipher.update(ByteArray(64))
    }

    fun split(chunk: ByteArray): List<ByteArray> {
        if (chunk.isEmpty()) return emptyList()
        if (disabled) return listOf(chunk)

        cipherBuf.write(chunk)
        plainBuf.write(cipher.update(chunk))

        val parts = mutableListOf<ByteArray>()
        val cipherArr = cipherBuf.toByteArray()
        val plainArr = plainBuf.toByteArray()
        var consumed = 0

        while (consumed < cipherArr.size) {
            val remaining = plainArr.size - consumed
            val packetLen = nextPacketLen(plainArr, consumed, remaining)

            if (packetLen == null) break // incomplete

            if (packetLen <= 0) {
                // Invalid — forward remaining and disable
                parts.add(cipherArr.copyOfRange(consumed, cipherArr.size))
                consumed = cipherArr.size
                disabled = true
                break
            }

            parts.add(cipherArr.copyOfRange(consumed, consumed + packetLen))
            consumed += packetLen
        }

        // Keep unconsumed data
        cipherBuf.reset()
        plainBuf.reset()
        if (consumed < cipherArr.size) {
            cipherBuf.write(cipherArr, consumed, cipherArr.size - consumed)
            plainBuf.write(plainArr, consumed, plainArr.size - consumed)
        }

        return parts
    }

    fun flush(): List<ByteArray> {
        val data = cipherBuf.toByteArray()
        cipherBuf.reset()
        plainBuf.reset()
        return if (data.isNotEmpty()) listOf(data) else emptyList()
    }

    private fun nextPacketLen(plain: ByteArray, offset: Int, remaining: Int): Int? {
        if (remaining == 0) return null
        return when (proto) {
            TelegramDC.PROTO_ABRIDGED -> nextAbridgedLen(plain, offset, remaining)
            TelegramDC.PROTO_INTERMEDIATE,
            TelegramDC.PROTO_PADDED_INTERMEDIATE -> nextIntermediateLen(plain, offset, remaining)
            else -> 0
        }
    }

    private fun nextAbridgedLen(plain: ByteArray, offset: Int, remaining: Int): Int? {
        val first = plain[offset].toInt() and 0xFF
        val headerLen: Int
        val payloadLen: Int

        if (first == 0x7F || first == 0xFF) {
            if (remaining < 4) return null
            payloadLen = ((plain[offset + 1].toInt() and 0xFF) or
                    ((plain[offset + 2].toInt() and 0xFF) shl 8) or
                    ((plain[offset + 3].toInt() and 0xFF) shl 16)) * 4
            headerLen = 4
        } else {
            payloadLen = (first and 0x7F) * 4
            headerLen = 1
        }

        if (payloadLen <= 0) return 0
        val packetLen = headerLen + payloadLen
        return if (remaining < packetLen) null else packetLen
    }

    private fun nextIntermediateLen(plain: ByteArray, offset: Int, remaining: Int): Int? {
        if (remaining < 4) return null
        val payloadLen = ByteBuffer.wrap(plain, offset, 4)
            .order(ByteOrder.LITTLE_ENDIAN).int and 0x7FFFFFFF
        if (payloadLen <= 0) return 0
        val packetLen = 4 + payloadLen
        return if (remaining < packetLen) null else packetLen
    }
}

/** Simple resettable byte buffer */
private class ByteArrayOutputStream {
    private var buf = ByteArray(4096)
    private var count = 0

    fun write(data: ByteArray) {
        write(data, 0, data.size)
    }

    fun write(data: ByteArray, off: Int, len: Int) {
        ensureCapacity(count + len)
        System.arraycopy(data, off, buf, count, len)
        count += len
    }

    fun toByteArray(): ByteArray = buf.copyOfRange(0, count)

    fun reset() { count = 0 }

    val size: Int get() = count

    private fun ensureCapacity(minCapacity: Int) {
        if (minCapacity > buf.size) {
            buf = buf.copyOf(maxOf(buf.size * 2, minCapacity))
        }
    }
}
