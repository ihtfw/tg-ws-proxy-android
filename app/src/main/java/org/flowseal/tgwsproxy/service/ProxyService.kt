package org.flowseal.tgwsproxy.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.util.Log
import androidx.core.app.NotificationCompat
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.ProxyServer
import org.flowseal.tgwsproxy.proxy.Stats
import org.flowseal.tgwsproxy.ui.MainActivity

/**
 * Foreground service that runs the SOCKS5→WebSocket proxy in the background.
 * Keeps running with a persistent notification even when the app UI is closed.
 */
class ProxyService : Service() {

    companion object {
        private const val TAG = "ProxyService"
        private const val CHANNEL_ID = "tg_ws_proxy"
        private const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "org.flowseal.tgwsproxy.STOP"
    }

    private var proxyServer: ProxyServer? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private val logBuffer = mutableListOf<String>()
    private val maxLogLines = 200

    // Binder for activity to query stats
    inner class LocalBinder : Binder() {
        fun getService(): ProxyService = this@ProxyService
    }
    private val binder = LocalBinder()

    val stats: Stats? get() = proxyServer?.stats
    val isProxyRunning: Boolean get() = proxyServer?.isRunning == true

    fun getRecentLogs(): List<String> = synchronized(logBuffer) { logBuffer.toList() }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopProxy()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        startForegroundWithNotification()
        acquireWakeLock()
        startProxy()

        return START_STICKY
    }

    override fun onDestroy() {
        stopProxy()
        releaseWakeLock()
        super.onDestroy()
    }

    private fun startProxy() {
        if (proxyServer?.isRunning == true) return

        val config = ProxyConfig(this)
        val dcOpt = config.parseDcOpt()

        if (dcOpt.isEmpty()) {
            addLog("No DC IPs configured, using defaults")
        }

        proxyServer = ProxyServer(
            host = config.host,
            port = config.port,
            dcOpt = dcOpt.ifEmpty { mapOf(2 to "149.154.167.220", 4 to "149.154.167.220") },
            poolSize = config.poolSize,
            bufKb = config.bufKb,
            onLog = { msg -> addLog(msg) }
        )
        proxyServer!!.start()
        updateNotification("Running on ${config.host}:${config.port}")
    }

    fun stopProxy() {
        proxyServer?.stop()
        proxyServer = null
    }

    fun restartProxy() {
        stopProxy()
        startProxy()
    }

    private fun addLog(msg: String) {
        synchronized(logBuffer) {
            logBuffer.add(msg)
            if (logBuffer.size > maxLogLines) {
                logBuffer.removeAt(0)
            }
        }
    }

    // --- Notification ---

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "TG WS Proxy",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps the proxy running in the background"
            setShowBadge(false)
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
    }

    private fun buildNotification(text: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val openPending = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPending = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("TG WS Proxy")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setContentIntent(openPending)
            .addAction(0, "Stop", stopPending)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    private fun startForegroundWithNotification() {
        val notification = buildNotification("Starting...")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    // --- Wake Lock ---

    private fun acquireWakeLock() {
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TgWsProxy::ProxyWakeLock")
        wakeLock?.acquire()
    }

    private fun releaseWakeLock() {
        wakeLock?.let {
            if (it.isHeld) it.release()
        }
        wakeLock = null
    }
}
