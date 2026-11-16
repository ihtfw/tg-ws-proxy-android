package org.flowseal.tgwsproxy.proxy

/**
 * Everything the proxy core is started with (upstream proxy/config.py ProxyConfig).
 * Immutable: a change of settings restarts the proxy with a new instance.
 */
data class ProxySettings(
    val host: String = "127.0.0.1",
    val port: Int = 1443,
    /** 32 hex characters; the client connects with "dd" + this, or "ee" + this + domain hex. */
    val secretHex: String = Bytes.toHex(Bytes.random(16)),
    /** DC -> IP to reach that DC's WebSocket through; DCs not listed go straight to the fallbacks. */
    val dcRedirects: Map<Int, String> = mapOf(2 to "149.154.167.220", 4 to "149.154.167.220"),
    val bufferSize: Int = 256 * 1024,
    /** Pre-opened WebSockets per DC; 0 disables direct WebSocket connections. */
    val poolSize: Int = 4,
    /** Fall back to Cloudflare-proxied domains (kwsN.<domain>) when the WebSocket fails. */
    val fallbackCfproxy: Boolean = true,
    /** The user's own Cloudflare-proxied domains; empty means the public list. */
    val cfproxyUserDomains: List<String> = emptyList(),
    /** The user's Cloudflare Worker domains, tried before the other fallbacks. */
    val cfproxyWorkerDomains: List<String> = emptyList(),
    /** Multiplex media connections over HTTP/2 to the Cloudflare proxy. */
    val cfproxyH2Media: Boolean = true,
    /** Plain port 80 instead of TLS on 443 for the CF proxy and CF worker. */
    val disableSecure: Boolean = false,
    /** Non-empty: accept only Fake TLS (ee) clients and mask as this domain. */
    val fakeTlsDomain: String = "",
    /** Send every connection to Telegram's test DCs. */
    val forceTestDc: Boolean = false,
) {
    val secret: ByteArray get() = Bytes.fromHex(secretHex)

    val h2Enabled: Boolean
        get() = cfproxyH2Media && fallbackCfproxy && !disableSecure && !forceTestDc

    /** The tg://proxy link a Telegram client is configured with. */
    fun proxyLink(linkHost: String = linkHost()): String {
        val secretParam = if (fakeTlsDomain.isNotEmpty()) {
            "ee" + secretHex + Bytes.toHex(fakeTlsDomain.toByteArray(Charsets.US_ASCII))
        } else {
            "dd$secretHex"
        }
        return "tg://proxy?server=$linkHost&port=$port&secret=$secretParam"
    }

    /** The address a client should use: the listen host, or this device's LAN address for 0.0.0.0. */
    fun linkHost(): String {
        if (host != "0.0.0.0") return host
        return try {
            java.net.DatagramSocket().use { s ->
                s.connect(java.net.InetAddress.getByName("8.8.8.8"), 80)
                s.localAddress.hostAddress ?: "127.0.0.1"
            }
        } catch (_: Exception) {
            "127.0.0.1"
        }
    }

    companion object {
        val DEFAULT_DC_IPS = listOf("2:149.154.167.220", "4:149.154.167.220")

        fun isValidSecret(hex: String): Boolean =
            hex.length == 32 && hex.all { Character.digit(it, 16) >= 0 }

        /** Parses "DC:IP" entries; throws IllegalArgumentException naming the bad entry. */
        fun parseDcIpList(entries: List<String>): Map<Int, String> {
            val result = linkedMapOf<Int, String>()
            for (raw in entries) {
                val entry = raw.trim()
                if (entry.isEmpty()) continue
                val idx = entry.indexOf(':')
                require(idx > 0) { "Invalid DC:IP entry '$entry', expected DC:IP" }
                val dc = entry.substring(0, idx).trim().toIntOrNull()
                val ip = entry.substring(idx + 1).trim()
                require(dc != null && isIpv4(ip)) { "Invalid DC:IP entry '$entry'" }
                result[dc] = ip
            }
            return result
        }

        fun isIpv4(s: String): Boolean {
            val parts = s.split('.')
            if (parts.size != 4) return false
            return parts.all { p -> p.isNotEmpty() && p.length <= 3 && p.all(Char::isDigit) && p.toInt() <= 255 }
        }

        /** Splits on commas, semicolons and whitespace, drops duplicates (case-insensitive). */
        fun coerceDomainList(value: String): List<String> {
            val seen = HashSet<String>()
            val out = ArrayList<String>()
            for (item in value.split(',', ';', ' ', '\n', '\t', '\r')) {
                val t = item.trim()
                if (t.isEmpty()) continue
                if (seen.add(t.lowercase())) out.add(t)
            }
            return out
        }
    }
}
