package org.flowseal.tgwsproxy.proxy

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.LinkedBlockingDeque

/**
 * WebSocket connection pool, keeping idle connections per DC.
 * Port of the Python _WsPool class.
 */
class WsPool(private val poolSize: Int = 4, private val maxAgeMs: Long = 120_000L) {

    private val TAG = "WsPool"

    private data class PoolEntry(val ws: RawWebSocket, val createdAt: Long)

    private val idle = ConcurrentHashMap<Pair<Int, Boolean>, LinkedBlockingDeque<PoolEntry>>()
    private val refilling = ConcurrentHashMap.newKeySet<Pair<Int, Boolean>>()

    val stats = Stats()

    fun get(dc: Int, isMedia: Boolean, targetIp: String, domains: List<String>): RawWebSocket? {
        if (poolSize <= 0) return null
        val key = dc to isMedia
        val bucket = idle[key] ?: return null.also {
            stats.poolMisses.incrementAndGet()
            scheduleRefill(key, targetIp, domains)
        }

        val now = System.currentTimeMillis()
        while (true) {
            val entry = bucket.pollFirst() ?: break
            val age = now - entry.createdAt
            if (age > maxAgeMs || entry.ws.isClosed) {
                closeQuietly(entry.ws)
                continue
            }
            stats.poolHits.incrementAndGet()
            Log.d(TAG, "Pool hit DC$dc${if (isMedia) "m" else ""} age=${age}ms left=${bucket.size}")
            scheduleRefill(key, targetIp, domains)
            return entry.ws
        }

        stats.poolMisses.incrementAndGet()
        scheduleRefill(key, targetIp, domains)
        return null
    }

    private fun scheduleRefill(key: Pair<Int, Boolean>, targetIp: String, domains: List<String>) {
        if (poolSize <= 0) return
        if (!refilling.add(key)) return
        Thread({
            try {
                refill(key, targetIp, domains)
            } finally {
                refilling.remove(key)
            }
        }, "ws-pool-refill-DC${key.first}${if (key.second) "m" else ""}").start()
    }

    private fun refill(key: Pair<Int, Boolean>, targetIp: String, domains: List<String>) {
        val bucket = idle.getOrPut(key) { LinkedBlockingDeque() }
        val needed = poolSize - bucket.size
        if (needed <= 0) return

        for (i in 0 until needed) {
            val ws = connectOne(targetIp, domains)
            if (ws != null) {
                bucket.addLast(PoolEntry(ws, System.currentTimeMillis()))
            }
        }
        Log.d(TAG, "Pool refilled DC${key.first}${if (key.second) "m" else ""}: ${bucket.size} ready")
    }

    private fun connectOne(targetIp: String, domains: List<String>): RawWebSocket? {
        for (domain in domains) {
            try {
                return RawWebSocket.connect(targetIp, domain, timeoutMs = 8000)
            } catch (e: WsHandshakeError) {
                if (e.isRedirect) continue
                return null
            } catch (_: Exception) {
                return null
            }
        }
        return null
    }

    fun warmup(dcOpt: Map<Int, String>) {
        for ((dc, targetIp) in dcOpt) {
            for (isMedia in listOf(false, true)) {
                val domains = TelegramDC.wsDomains(dc, isMedia)
                val key = dc to isMedia
                scheduleRefill(key, targetIp, domains)
            }
        }
        Log.i(TAG, "Pool warmup started for ${dcOpt.size} DC(s)")
    }

    fun shutdown() {
        for ((_, bucket) in idle) {
            while (true) {
                val entry = bucket.pollFirst() ?: break
                closeQuietly(entry.ws)
            }
        }
        idle.clear()
    }

    private fun closeQuietly(ws: RawWebSocket) {
        try { ws.close() } catch (_: Exception) {}
    }
}
