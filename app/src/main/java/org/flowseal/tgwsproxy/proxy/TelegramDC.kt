package org.flowseal.tgwsproxy.proxy

import android.util.Log
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Telegram DC IP mapping and utility functions.
 * Direct port of the Python proxy's DC detection logic.
 */
object TelegramDC {

    private const val TAG = "TelegramDC"

    // Telegram IP ranges for detection
    private val TG_RANGES: List<Pair<Long, Long>> = listOf(
        ipToLong("185.76.151.0") to ipToLong("185.76.151.255"),
        ipToLong("149.154.160.0") to ipToLong("149.154.175.255"),
        ipToLong("91.105.192.0") to ipToLong("91.105.193.255"),
        ipToLong("91.108.0.0") to ipToLong("91.108.255.255"),
    )

    // IP -> (dc_id, is_media)
    val IP_TO_DC: Map<String, Pair<Int, Boolean>> = mapOf(
        // DC1
        "149.154.175.50" to (1 to false), "149.154.175.51" to (1 to false),
        "149.154.175.53" to (1 to false), "149.154.175.54" to (1 to false),
        "149.154.175.52" to (1 to true),
        // DC2
        "149.154.167.41" to (2 to false), "149.154.167.50" to (2 to false),
        "149.154.167.51" to (2 to false), "149.154.167.220" to (2 to false),
        "95.161.76.100" to (2 to false),
        "149.154.167.151" to (2 to true), "149.154.167.222" to (2 to true),
        "149.154.167.223" to (2 to true), "149.154.162.123" to (2 to true),
        // DC3
        "149.154.175.100" to (3 to false), "149.154.175.101" to (3 to false),
        "149.154.175.102" to (3 to true),
        // DC4
        "149.154.167.91" to (4 to false), "149.154.167.92" to (4 to false),
        "149.154.164.250" to (4 to true), "149.154.166.120" to (4 to true),
        "149.154.166.121" to (4 to true), "149.154.167.118" to (4 to true),
        "149.154.165.111" to (4 to true),
        // DC5
        "91.108.56.100" to (5 to false), "91.108.56.101" to (5 to false),
        "91.108.56.116" to (5 to false), "91.108.56.126" to (5 to false),
        "149.154.171.5" to (5 to false),
        "91.108.56.102" to (5 to true), "91.108.56.128" to (5 to true),
        "91.108.56.151" to (5 to true),
        // DC203
        "91.105.192.100" to (203 to false),
    )

    val DC_OVERRIDES: Map<Int, Int> = mapOf(203 to 2)

    private fun ipToLong(ip: String): Long {
        val bytes = InetAddress.getByName(ip).address
        return ByteBuffer.wrap(bytes).int.toLong() and 0xFFFFFFFFL
    }

    fun isTelegramIp(ip: String): Boolean {
        return try {
            val n = ipToLong(ip)
            TG_RANGES.any { (lo, hi) -> n in lo..hi }
        } catch (_: Exception) {
            false
        }
    }

    fun isHttpTransport(data: ByteArray): Boolean {
        if (data.size < 4) return false
        val prefix = String(data, 0, minOf(8, data.size), Charsets.US_ASCII)
        return prefix.startsWith("POST ") || prefix.startsWith("GET ") ||
                prefix.startsWith("HEAD ") || prefix.startsWith("OPTIONS ")
    }

    fun wsDomains(dc: Int, isMedia: Boolean?): List<String> {
        val resolvedDc = DC_OVERRIDES.getOrDefault(dc, dc)
        return if (isMedia == null || isMedia) {
            listOf("kws${resolvedDc}-1.web.telegram.org", "kws${resolvedDc}.web.telegram.org")
        } else {
            listOf("kws${resolvedDc}.web.telegram.org", "kws${resolvedDc}-1.web.telegram.org")
        }
    }

    data class DcResult(
        val dc: Int?,
        val isMedia: Boolean,
        val proto: Int?
    )

    const val PROTO_ABRIDGED = 0xEFEFEFEF.toInt()
    const val PROTO_INTERMEDIATE = 0xEEEEEEEE.toInt()
    const val PROTO_PADDED_INTERMEDIATE = 0xDDDDDDDD.toInt()

    val VALID_PROTOS = setOf(PROTO_ABRIDGED, PROTO_INTERMEDIATE, PROTO_PADDED_INTERMEDIATE)

    private val ZERO_64 = ByteArray(64)

    /**
     * Extract DC ID from the 64-byte MTProto init packet using AES-CTR decryption.
     */
    fun dcFromInit(data: ByteArray): DcResult {
        if (data.size < 64) return DcResult(null, false, null)
        try {
            val key = data.copyOfRange(8, 40)
            val iv = data.copyOfRange(40, 56)

            val cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(key, "AES"),
                javax.crypto.spec.IvParameterSpec(iv)
            )
            val keystream = cipher.update(ZERO_64)

            // XOR bytes 56..63 of data with keystream to get plaintext
            val plain = ByteArray(8)
            for (i in 0 until 8) {
                plain[i] = (data[56 + i].toInt() xor keystream[56 + i].toInt()).toByte()
            }

            val buf = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN)
            val proto = buf.getInt(0)
            val dcRaw = buf.getShort(4).toInt()

            Log.d(TAG, "dc_from_init: proto=0x${proto.toUInt().toString(16)} dc_raw=$dcRaw")

            if (proto in VALID_PROTOS) {
                val dc = kotlin.math.abs(dcRaw)
                if (dc in 1..5 || dc == 203) {
                    return DcResult(dc, dcRaw < 0, proto)
                }
                return DcResult(null, false, proto)
            }
        } catch (e: Exception) {
            Log.d(TAG, "DC extraction failed: $e")
        }
        return DcResult(null, false, null)
    }

    /**
     * Patch dc_id in the 64-byte MTProto init packet.
     * Mobile clients with useSecret=0 leave bytes 60-61 as random.
     */
    fun patchInitDc(data: ByteArray, dc: Int): ByteArray {
        if (data.size < 64) return data
        try {
            val key = data.copyOfRange(8, 40)
            val iv = data.copyOfRange(40, 56)

            val cipher = javax.crypto.Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(
                javax.crypto.Cipher.ENCRYPT_MODE,
                javax.crypto.spec.SecretKeySpec(key, "AES"),
                javax.crypto.spec.IvParameterSpec(iv)
            )
            val ks = cipher.update(ZERO_64)

            val patched = data.copyOf()
            val newDcBytes = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
                .putShort(dc.toShort()).array()
            patched[60] = (ks[60].toInt() xor newDcBytes[0].toInt()).toByte()
            patched[61] = (ks[61].toInt() xor newDcBytes[1].toInt()).toByte()
            Log.d(TAG, "init patched: dc_id -> $dc")
            return patched
        } catch (_: Exception) {
            return data
        }
    }
}
