package org.flowseal.tgwsproxy.service

import android.content.Context
import android.content.SharedPreferences

/**
 * Configuration storage backed by SharedPreferences.
 */
class ProxyConfig(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("proxy_config", Context.MODE_PRIVATE)

    var host: String
        get() = prefs.getString("host", "127.0.0.1")!!
        set(value) = prefs.edit().putString("host", value).apply()

    var port: Int
        get() = prefs.getInt("port", 1080)
        set(value) = prefs.edit().putInt("port", value).apply()

    var dcIps: List<String>
        get() {
            val raw = prefs.getString("dc_ips", "2:149.154.167.220,4:149.154.167.220")!!
            return raw.split(",").filter { it.isNotBlank() }
        }
        set(value) = prefs.edit().putString("dc_ips", value.joinToString(",")).apply()

    var poolSize: Int
        get() = prefs.getInt("pool_size", 4)
        set(value) = prefs.edit().putInt("pool_size", value).apply()

    var bufKb: Int
        get() = prefs.getInt("buf_kb", 256)
        set(value) = prefs.edit().putInt("buf_kb", value).apply()

    var autostart: Boolean
        get() = prefs.getBoolean("autostart", false)
        set(value) = prefs.edit().putBoolean("autostart", value).apply()

    /** Theme mode: "system", "light", or "dark" */
    var themeMode: String
        get() = prefs.getString("theme_mode", "system") ?: "system"
        set(value) = prefs.edit().putString("theme_mode", value).apply()

    fun parseDcOpt(): Map<Int, String> {
        val result = mutableMapOf<Int, String>()
        for (entry in dcIps) {
            val parts = entry.split(":", limit = 2)
            if (parts.size == 2) {
                val dc = parts[0].trim().toIntOrNull() ?: continue
                val ip = parts[1].trim()
                if (ip.isNotEmpty()) result[dc] = ip
            }
        }
        return result
    }
}
