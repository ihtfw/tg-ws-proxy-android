package org.flowseal.tgwsproxy.service

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.flowseal.tgwsproxy.proxy.ProxyLog
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** The recent log lines the app shows; ProxyLog's sink writes here and to logcat. */
object LogBuffer {
    private const val TAG = "TgWsProxy"
    const val MAX_LINES = 2000

    private val lines = ArrayDeque<String>()
    private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private val _version = MutableStateFlow(0L)

    /** Changes whenever lines are added or cleared. */
    val version: StateFlow<Long> = _version.asStateFlow()

    @Volatile private var installed = false

    /** Routes the proxy core's log into logcat and this buffer; safe to call more than once. */
    fun install(context: Context) {
        ProxyLog.verbose = ProxyConfig(context).verbose
        if (installed) return
        synchronized(this) {
            if (installed) return
            ProxyLog.sink = { level, msg ->
                val priority = when (level) {
                    ProxyLog.Level.DEBUG -> Log.DEBUG
                    ProxyLog.Level.INFO -> Log.INFO
                    ProxyLog.Level.WARN -> Log.WARN
                    ProxyLog.Level.ERROR -> Log.ERROR
                }
                Log.println(priority, TAG, msg)
                add(level, msg)
            }
            installed = true
        }
    }

    fun add(level: ProxyLog.Level, msg: String) {
        synchronized(lines) {
            lines.addLast("${timeFormat.format(Date())} ${level.name.first()} $msg")
            while (lines.size > MAX_LINES) lines.removeFirst()
            _version.value = _version.value + 1
        }
    }

    fun snapshot(): List<String> = synchronized(lines) { lines.toList() }

    fun clear() {
        synchronized(lines) {
            lines.clear()
            _version.value = _version.value + 1
        }
    }
}
