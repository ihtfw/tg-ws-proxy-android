package org.flowseal.tgwsproxy.service

import org.flowseal.tgwsproxy.proxy.Bytes
import org.flowseal.tgwsproxy.proxy.ProxySettings

/** A settings field the user can get wrong. */
enum class ConfigField { HOST, PORT, SECRET, DC_IPS, CF_USER_DOMAINS, CF_WORKER_DOMAINS, POOL_SIZE, BUFFER }

/** What is wrong with a field; [entry] is the offending DC:IP line or domain when there is one. */
data class ConfigError(val field: ConfigField, val kind: Kind, val entry: String = "") {
    enum class Kind {
        BAD_HOST, BAD_PORT, SECRET_LENGTH, SECRET_HEX, DC_FORMAT, DC_INVALID, BAD_DOMAIN, BAD_POOL_SIZE, BAD_BUFFER,
    }
}

class ConfigException(val error: ConfigError) :
    IllegalArgumentException("${error.field}: ${error.kind}${if (error.entry.isNotEmpty()) " '${error.entry}'" else ""}")

/**
 * The proxy settings as the settings screen edits them: text fields stay text until validated.
 * Pure Kotlin (no android.*) so the validation runs in JVM unit tests; ProxyConfig loads and stores it.
 */
data class SettingsDraft(
    val host: String = DEFAULT_HOST,
    val port: String = DEFAULT_PORT.toString(),
    val secret: String = "",
    /** One DC:IP rule per line. */
    val dcIps: String = ProxySettings.DEFAULT_DC_IPS.joinToString("\n"),
    val poolSize: String = DEFAULT_POOL_SIZE.toString(),
    val bufKb: String = DEFAULT_BUF_KB.toString(),
    val forceTestDc: Boolean = false,
    /** Fall back to Cloudflare-proxied domains when a DC's WebSocket fails. */
    val cfproxy: Boolean = true,
    /** Use [cfUserDomains] instead of the public domain list. */
    val cfUserDomainEnabled: Boolean = false,
    /** The user's own Cloudflare-proxied domains, separated by commas. */
    val cfUserDomains: String = "",
    /** Multiplex media downloads over HTTP/2 to the CF proxy. */
    val h2Media: Boolean = true,
    val cfWorkerEnabled: Boolean = false,
    /** Cloudflare Worker domains, separated by commas. */
    val cfWorkerDomains: String = "",
    /** Plain port 80 instead of TLS for the CF proxy and CF worker. */
    val noSecure: Boolean = false,
) : java.io.Serializable {

    /** Listening on 0.0.0.0, reachable from other devices, instead of loopback only. */
    val listenAll: Boolean get() = host.trim() == ALL_INTERFACES

    fun withListenAll(on: Boolean): SettingsDraft = copy(host = if (on) ALL_INTERFACES else DEFAULT_HOST)

    fun dcIpLines(): List<String> = dcIps.lines().map { it.trim() }.filter { it.isNotEmpty() }

    /** HTTP/2 media needs the CF proxy over TLS and production DCs (ProxySettings.h2Enabled). */
    val h2Available: Boolean get() = cfproxy && !noSecure && !forceTestDc

    fun cfUserDomainList(): List<String> = ProxySettings.coerceDomainList(cfUserDomains)

    fun cfWorkerDomainList(): List<String> = ProxySettings.coerceDomainList(cfWorkerDomains)

    /** Every problem, at most one per field, in the order the fields appear on screen. */
    fun errors(): List<ConfigError> {
        val out = ArrayList<ConfigError>()
        if (!ProxySettings.isIpv4(host.trim())) out += ConfigError(ConfigField.HOST, ConfigError.Kind.BAD_HOST)
        if (parsePort(port) == null) out += ConfigError(ConfigField.PORT, ConfigError.Kind.BAD_PORT)
        secretError(secret.trim())?.let { out += it }
        dcError(dcIpLines())?.let { out += it }
        if (cfproxy && cfUserDomainEnabled) domainError(ConfigField.CF_USER_DOMAINS, cfUserDomainList())?.let { out += it }
        if (cfWorkerEnabled) domainError(ConfigField.CF_WORKER_DOMAINS, cfWorkerDomainList())?.let { out += it }
        if (parseInt(poolSize, 0, MAX_POOL_SIZE) == null) {
            out += ConfigError(ConfigField.POOL_SIZE, ConfigError.Kind.BAD_POOL_SIZE)
        }
        if (parseInt(bufKb, MIN_BUF_KB, MAX_BUF_KB) == null) {
            out += ConfigError(ConfigField.BUFFER, ConfigError.Kind.BAD_BUFFER)
        }
        return out
    }

    fun errorFor(field: ConfigField): ConfigError? = errors().firstOrNull { it.field == field }

    /**
     * The settings the proxy core starts with.
     * @throws ConfigException naming the first invalid field.
     */
    fun toProxySettings(): ProxySettings {
        errors().firstOrNull()?.let { throw ConfigException(it) }
        return ProxySettings(
            host = host.trim(),
            port = parsePort(port)!!,
            secretHex = secret.trim().lowercase(),
            dcRedirects = ProxySettings.parseDcIpList(dcIpLines()),
            bufferSize = parseInt(bufKb, MIN_BUF_KB, MAX_BUF_KB)!! * 1024,
            poolSize = parseInt(poolSize, 0, MAX_POOL_SIZE)!!,
            fallbackCfproxy = cfproxy,
            cfproxyUserDomains = if (cfproxy && cfUserDomainEnabled) cfUserDomainList() else emptyList(),
            cfproxyWorkerDomains = if (cfWorkerEnabled) cfWorkerDomainList() else emptyList(),
            cfproxyH2Media = h2Media,
            disableSecure = noSecure,
            forceTestDc = forceTestDc,
        )
    }

    companion object {
        private const val serialVersionUID = 1L

        const val DEFAULT_HOST = "127.0.0.1"
        const val ALL_INTERFACES = "0.0.0.0"
        const val DEFAULT_PORT = 1443
        const val DEFAULT_POOL_SIZE = 4
        const val DEFAULT_BUF_KB = 256
        const val MAX_POOL_SIZE = 64
        const val MIN_BUF_KB = 4
        const val MAX_BUF_KB = 16384

        /** A fresh random secret: 16 bytes as 32 hex characters. */
        fun newSecret(): String = Bytes.toHex(Bytes.random(16))

        fun parsePort(s: String): Int? = parseInt(s, 1, 65535)

        private fun parseInt(s: String, min: Int, max: Int): Int? =
            s.trim().toIntOrNull()?.takeIf { it in min..max }

        private fun secretError(secret: String): ConfigError? = when {
            secret.length != 32 -> ConfigError(ConfigField.SECRET, ConfigError.Kind.SECRET_LENGTH)
            !ProxySettings.isValidSecret(secret) -> ConfigError(ConfigField.SECRET, ConfigError.Kind.SECRET_HEX)
            else -> null
        }

        private val hostnamePattern =
            Regex("^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z0-9-]{2,63}$")

        /** A host name such as "example.com" or "name.account.workers.dev": no scheme, port or path. */
        fun isHostname(s: String): Boolean = hostnamePattern.matches(s) && !ProxySettings.isIpv4(s)

        private fun domainError(field: ConfigField, domains: List<String>): ConfigError? =
            domains.firstOrNull { !isHostname(it) }?.let { ConfigError(field, ConfigError.Kind.BAD_DOMAIN, it) }

        /** The first bad DC:IP line, told apart as "no DC:IP shape at all" or "bad DC number or IP". */
        private fun dcError(lines: List<String>): ConfigError? {
            for (line in lines) {
                try {
                    ProxySettings.parseDcIpList(listOf(line))
                } catch (_: IllegalArgumentException) {
                    val kind = if (line.indexOf(':') > 0) ConfigError.Kind.DC_INVALID else ConfigError.Kind.DC_FORMAT
                    return ConfigError(ConfigField.DC_IPS, kind, line)
                }
            }
            return null
        }
    }
}
