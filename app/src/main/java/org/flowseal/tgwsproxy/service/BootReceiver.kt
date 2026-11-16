package org.flowseal.tgwsproxy.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Starts the proxy service on device boot when "Start on boot" is on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return
        if (!ProxyConfig(context).autostart) return
        ProxyService.start(context)
    }
}
