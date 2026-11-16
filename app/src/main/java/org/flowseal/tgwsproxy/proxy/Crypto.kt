package org.flowseal.tgwsproxy.proxy

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** A streaming AES-256-CTR keystream; encrypting and decrypting are the same operation. */
class AesCtr(key: ByteArray, iv: ByteArray) {
    private val cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding").apply {
        init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
    }

    fun update(data: ByteArray): ByteArray = update(data, 0, data.size)

    fun update(data: ByteArray, offset: Int, length: Int): ByteArray {
        if (length == 0) return ByteArray(0)
        return cipher.update(data, offset, length) ?: ByteArray(0)
    }
}

/**
 * The four keystreams of one proxied connection (upstream bridge.CryptoCtx):
 * client ciphertext -> [cltDec] -> plain -> [tgEnc] -> Telegram, and back through [tgDec] and [cltEnc].
 */
class CryptoCtx(
    val cltDec: AesCtr,
    val cltEnc: AesCtr,
    val tgEnc: AesCtr,
    val tgDec: AesCtr,
)

object Bytes {
    val random = SecureRandom()

    fun random(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    fun toHex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) {
            val v = x.toInt() and 0xFF
            sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
        }
        return sb.toString()
    }

    /** Parses hex; throws IllegalArgumentException on odd length or a non-hex character. */
    fun fromHex(s: String): ByteArray {
        require(s.length % 2 == 0) { "odd hex length" }
        return ByteArray(s.length / 2) { i ->
            val hi = Character.digit(s[2 * i], 16)
            val lo = Character.digit(s[2 * i + 1], 16)
            require(hi >= 0 && lo >= 0) { "not hex" }
            ((hi shl 4) or lo).toByte()
        }
    }

    fun reversed(b: ByteArray): ByteArray = ByteArray(b.size) { b[b.size - 1 - it] }

    fun startsWith(b: ByteArray, prefix: ByteArray, at: Int = 0): Boolean {
        if (b.size - at < prefix.size) return false
        for (i in prefix.indices) if (b[at + i] != prefix[i]) return false
        return true
    }

    fun base64(data: ByteArray): String {
        val sb = StringBuilder((data.size + 2) / 3 * 4)
        var i = 0
        while (i < data.size) {
            val b0 = data[i].toInt() and 0xFF
            val b1 = if (i + 1 < data.size) data[i + 1].toInt() and 0xFF else 0
            val b2 = if (i + 2 < data.size) data[i + 2].toInt() and 0xFF else 0
            sb.append(B64[b0 ushr 2])
            sb.append(B64[((b0 and 3) shl 4) or (b1 ushr 4)])
            sb.append(if (i + 1 < data.size) B64[((b1 and 15) shl 2) or (b2 ushr 6)] else '=')
            sb.append(if (i + 2 < data.size) B64[b2 and 63] else '=')
            i += 3
        }
        return sb.toString()
    }

    fun u16be(b: ByteArray, off: Int): Int = ((b[off].toInt() and 0xFF) shl 8) or (b[off + 1].toInt() and 0xFF)

    fun u32le(b: ByteArray, off: Int): Long =
        (b[off].toLong() and 0xFF) or
            ((b[off + 1].toLong() and 0xFF) shl 8) or
            ((b[off + 2].toLong() and 0xFF) shl 16) or
            ((b[off + 3].toLong() and 0xFF) shl 24)

    private const val HEX = "0123456789abcdef"
    private const val B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
}

/** Reads exactly [n] bytes or throws EOFException. */
fun java.io.InputStream.readExactly(n: Int): ByteArray {
    val buf = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = read(buf, off, n - off)
        if (r < 0) throw java.io.EOFException("EOF after $off of $n bytes")
        off += r
    }
    return buf
}

/**
 * Checks that the peer certificate of [session] names [host] (subjectAltName DNS entries, one
 * left-most wildcard label allowed). Used instead of HttpsURLConnection's default verifier,
 * which on a desktop JVM rejects everything outside HttpsURLConnection.
 */
object HostCheck {
    fun matches(session: javax.net.ssl.SSLSession, host: String): Boolean {
        val cert = session.peerCertificates.firstOrNull() as? java.security.cert.X509Certificate ?: return false
        val names = cert.subjectAlternativeNames?.filter { it.size >= 2 && it[0] == 2 }?.map { it[1].toString() }
            ?: return false
        return names.any { nameMatches(it, host) }
    }

    fun nameMatches(pattern: String, host: String): Boolean {
        val p = pattern.lowercase().trimEnd('.')
        val h = host.lowercase().trimEnd('.')
        if (!p.startsWith("*.")) return p == h
        val suffix = p.substring(1) // ".web.telegram.org"
        if (!h.endsWith(suffix)) return false
        val left = h.substring(0, h.length - suffix.length)
        return left.isNotEmpty() && '.' !in left && suffix.count { it == '.' } >= 2
    }
}

/** An exception as "SimpleName: message", short and safe for the domain censor. */
fun errStr(e: Throwable): String = if (e.message.isNullOrEmpty()) e.javaClass.simpleName else "${e.javaClass.simpleName}: ${e.message}"
