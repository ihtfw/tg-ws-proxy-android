package org.flowseal.tgwsproxy.proxy

import java.util.concurrent.atomic.AtomicLong

/** Proxy connection and traffic statistics. */
class Stats {
    val connectionsTotal = AtomicLong(0)
    val connectionsWs = AtomicLong(0)
    val connectionsTcpFallback = AtomicLong(0)
    val connectionsHttpRejected = AtomicLong(0)
    val connectionsPassthrough = AtomicLong(0)
    val wsErrors = AtomicLong(0)
    val bytesUp = AtomicLong(0)
    val bytesDown = AtomicLong(0)
    val poolHits = AtomicLong(0)
    val poolMisses = AtomicLong(0)

    fun summary(): String {
        val ph = poolHits.get()
        val pm = poolMisses.get()
        return "total=${connectionsTotal.get()} ws=${connectionsWs.get()} " +
                "tcp_fb=${connectionsTcpFallback.get()} " +
                "http_skip=${connectionsHttpRejected.get()} " +
                "pass=${connectionsPassthrough.get()} " +
                "err=${wsErrors.get()} " +
                "pool=${ph}/${ph + pm} " +
                "up=${humanBytes(bytesUp.get())} " +
                "down=${humanBytes(bytesDown.get())}"
    }

    fun reset() {
        connectionsTotal.set(0)
        connectionsWs.set(0)
        connectionsTcpFallback.set(0)
        connectionsHttpRejected.set(0)
        connectionsPassthrough.set(0)
        wsErrors.set(0)
        bytesUp.set(0)
        bytesDown.set(0)
        poolHits.set(0)
        poolMisses.set(0)
    }

    companion object {
        fun humanBytes(n: Long): String {
            var value = n.toDouble()
            for (unit in listOf("B", "KB", "MB", "GB")) {
                if (kotlin.math.abs(value) < 1024) {
                    return "%.1f%s".format(value, unit)
                }
                value /= 1024
            }
            return "%.1f%s".format(value, "TB")
        }
    }
}
