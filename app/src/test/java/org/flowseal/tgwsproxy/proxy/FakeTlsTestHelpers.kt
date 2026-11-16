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
    /** A ClientHello built the way Telegram's client builds it, signed with [secret]. */
    fun telegramClientHello(domain: String, secret: ByteArray, timestamp: Long = Tls.nowSeconds()): ByteArray {
        val d = domain.toByteArray()
        val extensions = listOf(
            Tls.B().u16(0x0000).u16(d.size + 5).u16(d.size + 3).u8(0).u16(d.size).bytes(d),
            Tls.B().bytes(Bytes.fromHex("000500050100000000")),
            Tls.B().bytes(Bytes.fromHex("000a000c000a")).u16(0x4a4a).bytes(Bytes.fromHex("11ec001d00170018")),
            Tls.B().bytes(Bytes.fromHex("000b00020100")),
            Tls.B().bytes(Bytes.fromHex("000d0012001004030804040105030805050108060601")),
            Tls.B().bytes(Bytes.fromHex("0010000e000c02683208687474702f312e31")),
            Tls.B().bytes(Bytes.fromHex("00120000")),
            Tls.B().bytes(Bytes.fromHex("00170000")),
            Tls.B().bytes(Bytes.fromHex("001b0003020002")),
            Tls.B().bytes(Bytes.fromHex("00230000")),
            Tls.B().bytes(Bytes.fromHex("002b000706")).u16(0x6a6a).bytes(Bytes.fromHex("03040303")),
            Tls.B().bytes(Bytes.fromHex("002d00020101")),
            Tls.B().bytes(Bytes.fromHex("003304ef04ed")).u16(0x4a4a).bytes(Bytes.fromHex("00010011ec04c0"))
                .bytes(Bytes.random(1184)).bytes(X25519.publicKey(X25519.generatePrivateKey()))
                .bytes(Bytes.fromHex("001d0020")).bytes(X25519.publicKey(X25519.generatePrivateKey())),
            Tls.B().bytes(Bytes.fromHex("44cd00050003026832")),
            Tls.B().u16(0xfe0d).u16(5 + 1 + 2 + 32 + 2 + 144).bytes(Bytes.fromHex("0000010001"))
                .bytes(Bytes.random(1)).u16(32).bytes(Bytes.random(32)).u16(144).bytes(Bytes.random(144)),
            Tls.B().bytes(Bytes.fromHex("ff01000100")),
        ).map { it.toByteArray() }.shuffled()

        val ext = Tls.B().u16(0x2a2a).u16(0)
        extensions.forEach { ext.bytes(it) }
        ext.u16(0x3a3a).bytes(Bytes.fromHex("000100"))
        val extBytes = ext.toByteArray()

        val hello = Tls.B().u16(0x0303).bytes(ByteArray(32)).u8(0x20).bytes(Bytes.random(32))
            .u16(0x0020).u16(0x0a0a)
            .bytes(Bytes.fromHex("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035"))
            .bytes(Bytes.fromHex("0100")).u16(extBytes.size).bytes(extBytes)
            .toByteArray()
        val message = Tls.B().u8(0x01).u24(hello.size).bytes(hello).toByteArray()
        val record = Tls.B().u8(0x16).u16(0x0301).u16(message.size).bytes(message).toByteArray()
        return Tls.sign(record, secret, timestamp)
    }

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
