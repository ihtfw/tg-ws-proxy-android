package org.flowseal.tgwsproxy.service

import android.content.Context
import android.content.SharedPreferences
import org.flowseal.tgwsproxy.proxy.ProxySettings

/**
 * Settings storage backed by SharedPreferences, with upstream's defaults
 * (utils/default_config.py): MTProto on 127.0.0.1:1443 with a secret generated once.
 */
class ProxyConfig(context: Context) {

    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    init {
        synchronized(LOCK) { migrate() }
    }

    var host: String
        get() = prefs.getString(KEY_HOST, null) ?: SettingsDraft.DEFAULT_HOST
        set(value) = prefs.edit().putString(KEY_HOST, value).apply()

    var port: Int
        get() = prefs.getInt(KEY_PORT, SettingsDraft.DEFAULT_PORT)
        set(value) = prefs.edit().putInt(KEY_PORT, value).apply()

    /** 32 hex characters; created on first use and kept until the user regenerates it. */
    val secret: String
        get() = prefs.getString(KEY_SECRET, null).orEmpty()

    var dcIps: List<String>
        get() = (prefs.getString(KEY_DC_IPS, null) ?: ProxySettings.DEFAULT_DC_IPS.joinToString(","))
            .split(',', '\n').map { it.trim() }.filter { it.isNotEmpty() }
        set(value) = prefs.edit().putString(KEY_DC_IPS, value.joinToString(",")).apply()

    var poolSize: Int
        get() = prefs.getInt(KEY_POOL_SIZE, SettingsDraft.DEFAULT_POOL_SIZE)
        set(value) = prefs.edit().putInt(KEY_POOL_SIZE, value).apply()

    var bufKb: Int
        get() = prefs.getInt(KEY_BUF_KB, SettingsDraft.DEFAULT_BUF_KB)
        set(value) = prefs.edit().putInt(KEY_BUF_KB, value).apply()

    var forceTestDc: Boolean
        get() = prefs.getBoolean(KEY_FORCE_TEST_DC, false)
        set(value) = prefs.edit().putBoolean(KEY_FORCE_TEST_DC, value).apply()

    var cfproxy: Boolean
        get() = prefs.getBoolean(KEY_CFPROXY, true)
        set(value) = prefs.edit().putBoolean(KEY_CFPROXY, value).apply()

    var cfproxyUserDomainEnabled: Boolean
        get() = prefs.getBoolean(KEY_CF_USER_DOMAIN_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_CF_USER_DOMAIN_ENABLED, value).apply()

    var cfproxyUserDomains: List<String>
        get() = ProxySettings.coerceDomainList(prefs.getString(KEY_CF_USER_DOMAINS, null).orEmpty())
        set(value) = prefs.edit().putString(KEY_CF_USER_DOMAINS, value.joinToString(",")).apply()

    /** Media over HTTP/2 to the CF proxy. */
    var h2Media: Boolean
        get() = prefs.getBoolean(KEY_H2, true)
        set(value) = prefs.edit().putBoolean(KEY_H2, value).apply()

    var cfproxyWorkerEnabled: Boolean
        get() = prefs.getBoolean(KEY_CF_WORKER_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_CF_WORKER_ENABLED, value).apply()

    var cfproxyWorkerDomains: List<String>
        get() = ProxySettings.coerceDomainList(prefs.getString(KEY_CF_WORKER_DOMAINS, null).orEmpty())
        set(value) = prefs.edit().putString(KEY_CF_WORKER_DOMAINS, value.joinToString(",")).apply()

    /** Port 80 without TLS for the CF proxy and CF worker. */
    var noSecure: Boolean
        get() = prefs.getBoolean(KEY_NO_SECURE, false)
        set(value) = prefs.edit().putBoolean(KEY_NO_SECURE, value).apply()

    /** Start the proxy when the device boots. */
    var autostart: Boolean
        get() = prefs.getBoolean(KEY_AUTOSTART, false)
        set(value) = prefs.edit().putBoolean(KEY_AUTOSTART, value).apply()

    /** "system", "light" or "dark". */
    var themeMode: String
        get() = prefs.getString(KEY_THEME, null) ?: "system"
        set(value) = prefs.edit().putString(KEY_THEME, value).apply()

    /** Debug lines in the log. */
    var verbose: Boolean
        get() = prefs.getBoolean(KEY_VERBOSE, false)
        set(value) = prefs.edit().putBoolean(KEY_VERBOSE, value).apply()

    /** The stored proxy settings in the shape the settings screen edits. */
    fun draft(): SettingsDraft = SettingsDraft(
        host = host,
        port = port.toString(),
        secret = secret,
        dcIps = dcIps.joinToString("\n"),
        poolSize = poolSize.toString(),
        bufKb = bufKb.toString(),
        forceTestDc = forceTestDc,
        cfproxy = cfproxy,
        cfUserDomainEnabled = cfproxyUserDomainEnabled,
        cfUserDomains = cfproxyUserDomains.joinToString(", "),
        h2Media = h2Media,
        cfWorkerEnabled = cfproxyWorkerEnabled,
        cfWorkerDomains = cfproxyWorkerDomains.joinToString(", "),
        noSecure = noSecure,
    )

    /**
     * Stores [draft] if it is valid.
     * @throws ConfigException naming the first invalid field; nothing is stored then.
     */
    fun save(draft: SettingsDraft) {
        val s = draft.toProxySettings()
        prefs.edit()
            .putString(KEY_HOST, s.host)
            .putInt(KEY_PORT, s.port)
            .putString(KEY_SECRET, s.secretHex)
            .putString(KEY_DC_IPS, draft.dcIpLines().joinToString(","))
            .putInt(KEY_POOL_SIZE, s.poolSize)
            .putInt(KEY_BUF_KB, s.bufferSize / 1024)
            .putBoolean(KEY_FORCE_TEST_DC, s.forceTestDc)
            .putBoolean(KEY_CFPROXY, draft.cfproxy)
            .putBoolean(KEY_CF_USER_DOMAIN_ENABLED, draft.cfUserDomainEnabled)
            .putString(KEY_CF_USER_DOMAINS, draft.cfUserDomainList().joinToString(","))
            .putBoolean(KEY_H2, draft.h2Media)
            .putBoolean(KEY_CF_WORKER_ENABLED, draft.cfWorkerEnabled)
            .putString(KEY_CF_WORKER_DOMAINS, draft.cfWorkerDomainList().joinToString(","))
            .putBoolean(KEY_NO_SECURE, draft.noSecure)
            .apply()
    }

    /**
     * What the proxy core starts with.
     * @throws ConfigException when a stored value is invalid (a bad DC:IP rule, a bad secret...).
     */
    fun toProxySettings(): ProxySettings = draft().toProxySettings()

    private fun migrate() {
        val version = prefs.getInt(KEY_SCHEMA, 0)
        if (version >= SCHEMA_VERSION && prefs.contains(KEY_SECRET)) return
        val edit = prefs.edit()
        if (version < 1) {
            // Schema 0 was the SOCKS5 proxy, whose default port 1080 was saved under the same key.
            if (prefs.contains(KEY_PORT) && prefs.getInt(KEY_PORT, 0) == LEGACY_SOCKS_PORT) {
                edit.putInt(KEY_PORT, SettingsDraft.DEFAULT_PORT)
            }
        }
        if (prefs.getString(KEY_SECRET, null).isNullOrEmpty()) {
            edit.putString(KEY_SECRET, SettingsDraft.newSecret())
        }
        edit.putInt(KEY_SCHEMA, SCHEMA_VERSION)
        edit.commit()
    }

    companion object {
        private val LOCK = Any()
        private const val PREFS_NAME = "proxy_config"
        const val SCHEMA_VERSION = 1
        private const val LEGACY_SOCKS_PORT = 1080

        private const val KEY_SCHEMA = "schema_version"
        private const val KEY_HOST = "host"
        private const val KEY_PORT = "port"
        private const val KEY_SECRET = "secret"
        private const val KEY_DC_IPS = "dc_ips"
        private const val KEY_POOL_SIZE = "pool_size"
        private const val KEY_BUF_KB = "buf_kb"
        private const val KEY_FORCE_TEST_DC = "force_test_dc"
        private const val KEY_CFPROXY = "cfproxy"
        private const val KEY_CF_USER_DOMAIN_ENABLED = "cfproxy_user_domain_enabled"
        private const val KEY_CF_USER_DOMAINS = "cfproxy_user_domain"
        private const val KEY_H2 = "h2"
        private const val KEY_CF_WORKER_ENABLED = "cfproxy_worker_enabled"
        private const val KEY_CF_WORKER_DOMAINS = "cfproxy_worker_domain"
        private const val KEY_NO_SECURE = "no_secure"
        private const val KEY_AUTOSTART = "autostart"
        private const val KEY_THEME = "theme_mode"
        private const val KEY_VERBOSE = "verbose"
    }
}
