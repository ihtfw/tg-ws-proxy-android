package org.flowseal.tgwsproxy.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import org.flowseal.tgwsproxy.R
import org.flowseal.tgwsproxy.proxy.ProxyLog
import org.flowseal.tgwsproxy.proxy.ProxyServer
import org.flowseal.tgwsproxy.proxy.ProxySettings
import org.flowseal.tgwsproxy.ui.MainActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Foreground service that runs the local MTProto proxy with a persistent notification,
 * also when the app UI is closed. Starting and stopping happen on one background thread
 * so a restart never races the previous listener for the port.
 */
class ProxyService : Service() {

    companion object {
        private const val CHANNEL_ID = "tg_ws_proxy"
        private const val NOTIFICATION_ID = 1
        const val ACTION_START = "org.flowseal.tgwsproxy.START"
        const val ACTION_STOP = "org.flowseal.tgwsproxy.STOP"
        const val ACTION_RESTART = "org.flowseal.tgwsproxy.RESTART"

        /** Serializes start/stop across service instances. */
        private val control: ExecutorService = Executors.newSingleThreadExecutor { r ->
            Thread(r, "proxy-control").apply { isDaemon = true }
        }

        /** Touched only on the control thread. */
        private var server: ProxyServer? = null

        /** False once the user asked to stop; late results then stay out of the notification. */
        @Volatile private var wanted = false

        fun start(context: Context) = startForeground(context, ACTION_START)

        fun restart(context: Context) = startForeground(context, ACTION_RESTART)

        fun stop(context: Context) {
            context.startService(Intent(context, ProxyService::class.java).setAction(ACTION_STOP))
        }

        private fun startForeground(context: Context, action: String) {
            ContextCompat.startForegroundService(
                context, Intent(context, ProxyService::class.java).setAction(action)
            )
        }
    }

    private var wakeLock: PowerManager.WakeLock? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        LogBuffer.install(applicationContext)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                wanted = false
                control.execute { stopServer() }
                releaseWakeLock()
                ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_RESTART -> {
                wanted = true
                goForeground()
                control.execute {
                    stopServer()
                    startServer()
                }
            }
            else -> {
                // ACTION_START, or a null intent when the system restarts a sticky service.
                wanted = true
                goForeground()
                control.execute { if (server == null) startServer() }
            }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        if (wanted) {
            // Destroyed without a Stop request (the system reclaimed it): shut the listener too.
            wanted = false
            control.execute { stopServer() }
        }
        releaseWakeLock()
        super.onDestroy()
    }

    /** On the control thread. */
    private fun startServer() {
        ProxyState.set(ProxyState.Status.Starting)
        val config = ProxyConfig(this)
        ProxyLog.verbose = config.verbose

        val settings = try {
            config.toProxySettings()
        } catch (e: ConfigException) {
            ProxyLog.e("Invalid settings: ${e.message}")
            fail(getString(R.string.error_config, e.error.message(this)))
            return
        }

        ProxyLog.i("Starting MTProto proxy on ${settings.host}:${settings.port}")
        val srv = ProxyServer(settings)
        try {
            srv.start()
        } catch (e: Exception) {
            try {
                srv.stop()
            } catch (_: Exception) {
            }
            ProxyLog.e("Failed to start proxy on ${settings.host}:${settings.port}: $e")
            fail(listenErrorMessage(this, e, settings.port))
            return
        }
        server = srv
        ProxyState.stats = srv.stats
        val running = runningStatus(settings)
        ProxyState.set(running)
        ProxyLog.i("Proxy listening on ${running.listen}")
        if (!wanted) return
        acquireWakeLock()
        updateNotification()
    }

    /** On the control thread. */
    private fun stopServer() {
        val srv = server
        if (srv == null) {
            ProxyState.set(ProxyState.Status.Stopped)
            return
        }
        server = null
        try {
            srv.stop()
        } catch (e: Exception) {
            ProxyLog.w("Error while stopping proxy: $e")
        }
        ProxyState.stats = null
        ProxyState.set(ProxyState.Status.Stopped)
        ProxyLog.i("Proxy stopped")
    }

    private fun fail(message: String) {
        ProxyState.stats = null
        ProxyState.set(ProxyState.Status.Failed(message))
        releaseWakeLock()
        if (wanted) updateNotification()
    }

    private fun runningStatus(settings: ProxySettings): ProxyState.Status.Running {
        val all = settings.host == SettingsDraft.ALL_INTERFACES
        val localHost = if (all) SettingsDraft.DEFAULT_HOST else settings.host
        val lanHost = if (all) settings.linkHost() else null
        return ProxyState.Status.Running(
            listen = "${settings.host}:${settings.port}",
            localLink = settings.proxyLink(localHost),
            lanLink = lanHost?.takeIf { it != SettingsDraft.DEFAULT_HOST }?.let { settings.proxyLink(it) },
        )
    }

    // --- Notification ---

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = getString(R.string.notification_channel_description)
            setShowBadge(false)
        }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun buildNotification(): Notification {
        val openPending = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPending = PendingIntent.getService(
            this, 1,
            Intent(this, ProxyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setContentIntent(openPending)
            .addAction(0, getString(R.string.action_stop), stopPending)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)

        when (val status = ProxyState.status.value) {
            is ProxyState.Status.Running -> builder
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.notification_listening, status.listen))
            is ProxyState.Status.Failed -> builder
                .setContentTitle(getString(R.string.notification_failed_title))
                .setContentText(status.message.lineSequence().drop(1).firstOrNull { it.isNotBlank() } ?: status.message)
                .setStyle(NotificationCompat.BigTextStyle().bigText(status.message))
            else -> builder
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.notification_starting))
        }
        return builder.build()
    }

    private fun goForeground() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), type)
    }

    private fun updateNotification() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification())
    }

    // --- Wake lock ---

    @Synchronized
    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return
        val pm = getSystemService(POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "TgWsProxy::ProxyWakeLock").apply {
            setReferenceCounted(false)
            acquire()
        }
    }

    @Synchronized
    private fun releaseWakeLock() {
        wakeLock?.let { if (it.isHeld) it.release() }
        wakeLock = null
    }
}
