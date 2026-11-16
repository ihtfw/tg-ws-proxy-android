package org.flowseal.tgwsproxy.proxy

/** MTProto obfuscation constants and Telegram DC tables (upstream proxy/utils.py). */
object MtConst {
    const val HANDSHAKE_LEN = 64
    const val SKIP_LEN = 8
    const val PREKEY_LEN = 32
    const val KEY_LEN = 32
    const val IV_LEN = 16
    const val PROTO_TAG_POS = 56
    const val DC_IDX_POS = 60

    val ZERO_64 = ByteArray(64)

    val PROTO_TAG_ABRIDGED = byteArrayOf(0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte(), 0xEF.toByte())
    val PROTO_TAG_INTERMEDIATE = byteArrayOf(0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte(), 0xEE.toByte())
    val PROTO_TAG_SECURE = byteArrayOf(0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte(), 0xDD.toByte())

    const val PROTO_ABRIDGED_INT = 0xEFEFEFEF.toInt()
    const val PROTO_INTERMEDIATE_INT = 0xEEEEEEEE.toInt()
    const val PROTO_PADDED_INTERMEDIATE_INT = 0xDDDDDDDD.toInt()

    val RESERVED_FIRST_BYTES = setOf(0xEF)
    val RESERVED_STARTS: List<ByteArray> = listOf(
        byteArrayOf(0x48, 0x45, 0x41, 0x44),               // HEAD
        byteArrayOf(0x50, 0x4F, 0x53, 0x54),               // POST
        byteArrayOf(0x47, 0x45, 0x54, 0x20),               // GET
        PROTO_TAG_INTERMEDIATE,
        PROTO_TAG_SECURE,
        byteArrayOf(0x16, 0x03, 0x01, 0x02),               // TLS
        byteArrayOf(0x4F, 0x50, 0x54, 0x49),               // OPTI
    )
    val RESERVED_CONTINUE = ByteArray(4)

    /** Where a DC goes when its WebSocket is not available (direct TCP and CF worker target). */
    val DC_DEFAULT_IPS: Map<Int, String> = linkedMapOf(
        1 to "149.154.175.50",
        2 to "149.154.167.51",
        3 to "149.154.175.100",
        4 to "149.154.167.91",
        5 to "149.154.171.5",
        203 to "91.105.192.100",
    )

    val DC_TEST_IPS: Map<Int, String> = linkedMapOf(
        1 to "149.154.175.10",
        2 to "149.154.167.40",
        3 to "149.154.175.117",
    )

    /** DC ids the Cloudflare proxy balancer knows. */
    val CF_DCS = listOf(1, 2, 3, 4, 5, 203)

    const val WS_PATH = "/apiws"
    const val WS_PATH_TEST = "/apiws_test"

    /** SNI used for the "fronted" WebSocket connection attempt (upstream pool.py). */
    const val FRONTING_SNI = "sprinthost.ru"

    fun protoInt(tag: ByteArray): Int = when {
        tag.contentEquals(PROTO_TAG_ABRIDGED) -> PROTO_ABRIDGED_INT
        tag.contentEquals(PROTO_TAG_INTERMEDIATE) -> PROTO_INTERMEDIATE_INT
        else -> PROTO_PADDED_INTERMEDIATE_INT
    }
}

fun wsDomains(dc: Int, isMedia: Boolean): List<String> {
    val d = if (dc == 203) 2 else dc
    return if (!isMedia) listOf("kws$d.web.telegram.org")
    else listOf("kws$d-1.web.telegram.org", "kws$d.web.telegram.org")
}

fun humanBytes(n: Long): String {
    var value = n.toDouble()
    for (unit in listOf("B", "KB", "MB", "GB")) {
        if (kotlin.math.abs(value) < 1024) return String.format(java.util.Locale.US, "%.1f%s", value, unit)
        value /= 1024
    }
    return String.format(java.util.Locale.US, "%.1f%s", value, "TB")
}

fun dcTag(dc: Int, isMedia: Boolean, isTest: Boolean = false): String =
    "DC$dc${if (isTest) "t" else ""}${if (isMedia) "m" else ""}"
