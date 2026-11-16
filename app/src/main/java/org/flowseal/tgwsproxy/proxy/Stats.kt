package org.flowseal.tgwsproxy.proxy

import java.util.concurrent.atomic.AtomicLong

/** Connection and traffic counters (upstream proxy/stats.py). */
class Stats {
    val connectionsTotal = AtomicLong()
    val connectionsActive = AtomicLong()
    val connectionsWs = AtomicLong()
    val connectionsH2 = AtomicLong()
    val h2TcpConnections = AtomicLong()
    val h2Requests = AtomicLong()
    val h2Errors = AtomicLong()
    val connectionsTcpFallback = AtomicLong()
    val connectionsCfproxy = AtomicLong()
    val connectionsFronting = AtomicLong()
    val connectionsBad = AtomicLong()
    val connectionsMasked = AtomicLong()
    val wsErrors = AtomicLong()
    val bytesUp = AtomicLong()
    val bytesDown = AtomicLong()
    val poolHits = AtomicLong()
    val poolMisses = AtomicLong()
    val cfPoolHits = AtomicLong()
    val cfPoolMisses = AtomicLong()

    fun summary(): String {
        val pool = poolHits.get() + poolMisses.get()
        val cfPool = cfPoolHits.get() + cfPoolMisses.get()
        return "total=${connectionsTotal.get()} active=${connectionsActive.get()} " +
            "ws=${connectionsWs.get()} h2=${connectionsH2.get()} h2_tcp=${h2TcpConnections.get()} " +
            "h2_req=${h2Requests.get()} h2_err=${h2Errors.get()} " +
            "tcp_fb=${connectionsTcpFallback.get()} cf=${connectionsCfproxy.get()} " +
            "front=${connectionsFronting.get()} bad=${connectionsBad.get()} " +
            "masked=${connectionsMasked.get()} err=${wsErrors.get()} " +
            "pool=${if (pool > 0) "${poolHits.get()}/$pool" else "n/a"} " +
            "cf_pool=${if (cfPool > 0) "${cfPoolHits.get()}/$cfPool" else "n/a"} " +
            "up=${humanBytes(bytesUp.get())} down=${humanBytes(bytesDown.get())}"
    }
}
