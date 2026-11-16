package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayOutputStream
import org.flowseal.tgwsproxy.proxy.FakeTls.CLIENT_RANDOM_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.CLIENT_RANDOM_OFFSET
import org.flowseal.tgwsproxy.proxy.FakeTls.EXT_KEY_SHARE
import org.flowseal.tgwsproxy.proxy.FakeTls.EXT_SUPPORTED_VERSIONS
import org.flowseal.tgwsproxy.proxy.FakeTls.GROUP_X25519
import org.flowseal.tgwsproxy.proxy.FakeTls.GROUP_X25519MLKEM768
import org.flowseal.tgwsproxy.proxy.FakeTls.SESSION_ID_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.SESSION_ID_OFFSET
import org.flowseal.tgwsproxy.proxy.FakeTls.TLS_RECORD_HANDSHAKE
import org.flowseal.tgwsproxy.proxy.FakeTls.X25519MLKEM768_CLIENT_SHARE_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.X25519_KEY_LEN

/** ClientHellos and records as the tests of upstream's tests/test_fake_tls.py build them. */
object Tls {
    val SECRET: ByteArray = Bytes.fromHex("00112233445566778899aabbccddeeff")

    /** Telegram's current ClientHello offers these, like Chrome. */
    val TELEGRAM_SUITES = listOf(0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f)
    val TELEGRAM_SHARES = listOf(
        GROUP_X25519MLKEM768 to X25519MLKEM768_CLIENT_SHARE_LEN,
        GROUP_X25519 to X25519_KEY_LEN,
    )

    fun nowSeconds(): Long = System.currentTimeMillis() / 1000

    class B : ByteArrayOutputStream() {
        fun u8(v: Int) = apply { write(v and 0xFF) }
        fun u16(v: Int) = apply { write((v ushr 8) and 0xFF); write(v and 0xFF) }
        fun u24(v: Int) = apply { write((v ushr 16) and 0xFF); u16(v) }
        fun bytes(b: ByteArray) = apply { write(b, 0, b.size) }
    }

    /** Puts HMAC(secret, body) into the client random, its last 4 bytes XORed with [timestamp]. */
    fun sign(body: ByteArray, secret: ByteArray, timestamp: Long): ByteArray {
        val digest = Bytes.hmacSha256(secret, body)
        val clientRandom = digest.copyOf(CLIENT_RANDOM_LEN)
        for (i in 0 until 4) {
            clientRandom[28 + i] = (digest[28 + i].toInt() xor (timestamp ushr (8 * i)).toInt()).toByte()
        }
        System.arraycopy(clientRandom, 0, body, CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_LEN)
        return body
    }

    fun structuredClientHello(
        suites: List<Int> = TELEGRAM_SUITES,
        shares: List<Pair<Int, Int>> = TELEGRAM_SHARES,
        secret: ByteArray = SECRET,
        timestamp: Long = nowSeconds(),
    ): ByteArray {
        val keyShareList = B().apply {
            for ((group, length) in shares) u16(group).u16(length).bytes(Bytes.random(length))
        }.toByteArray()
        val extensions = B()
            .u16(0x0000).u16(0)
            .u16(EXT_KEY_SHARE).u16(2 + keyShareList.size).u16(keyShareList.size).bytes(keyShareList)
            .u16(EXT_SUPPORTED_VERSIONS).u16(3).u8(2).bytes(byteArrayOf(0x03, 0x04))
            .toByteArray()
        val hello = B()
            .u16(0x0303).bytes(ByteArray(CLIENT_RANDOM_LEN))
            .u8(0x20).bytes(Bytes.random(SESSION_ID_LEN))
            .u16(2 * suites.size).apply { for (s in suites) u16(s) }
            .u8(1).u8(0)
            .u16(extensions.size).bytes(extensions)
            .toByteArray()
        val message = B().u8(0x01).u24(hello.size).bytes(hello).toByteArray()
        val body = B().u8(0x16).u16(0x0301).u16(message.size).bytes(message).toByteArray()
        return sign(body, secret, timestamp)
    }

    /** A 517-byte hello that is zeros apart from what the HMAC check reads. */
    fun clientHello(
        secret: ByteArray = SECRET,
        timestamp: Long = nowSeconds(),
        sessionId: ByteArray = Bytes.random(SESSION_ID_LEN),
    ): ByteArray {
        val body = ByteArray(517)
        body[0] = TLS_RECORD_HANDSHAKE.toByte()
        body[1] = 0x03
        body[2] = 0x01
        body[3] = ((body.size - 5) ushr 8).toByte()
        body[4] = (body.size - 5).toByte()
        body[5] = 0x01
        body[43] = 0x20
        System.arraycopy(sessionId, 0, body, SESSION_ID_OFFSET, SESSION_ID_LEN)
        return sign(body, secret, timestamp)
    }

    fun splitRecords(data: ByteArray): List<Pair<Int, ByteArray>> {
        val records = ArrayList<Pair<Int, ByteArray>>()
        var pos = 0
        while (pos < data.size) {
            val type = data[pos].toInt() and 0xFF
            val length = Bytes.u16be(data, pos + 3)
            records.add(type to data.copyOfRange(pos + 5, pos + 5 + length))
            pos += 5 + length
        }
        return records
    }

    /** The cipher suite and extensions of a ServerHello handshake message. */
    fun serverHelloFields(record: ByteArray): Pair<Int, List<Pair<Int, ByteArray>>> {
        var pos = 4 + 2 + 32
        pos += 1 + (record[pos].toInt() and 0xFF)
        val cipher = Bytes.u16be(record, pos)
        pos += 3
        val extEnd = pos + 2 + Bytes.u16be(record, pos)
        pos += 2
        val extensions = ArrayList<Pair<Int, ByteArray>>()
        while (pos < extEnd) {
            val type = Bytes.u16be(record, pos)
            val len = Bytes.u16be(record, pos + 2)
            extensions.add(type to record.copyOfRange(pos + 4, pos + 4 + len))
            pos += 4 + len
        }
        return cipher to extensions
    }

    fun record(type: Int, length: Int, payload: ByteArray = ByteArray(length)): ByteArray =
        B().u8(type).u16(0x0303).u16(length).bytes(payload).toByteArray()
}
