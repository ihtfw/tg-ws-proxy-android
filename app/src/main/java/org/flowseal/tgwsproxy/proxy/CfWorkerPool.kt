package org.flowseal.tgwsproxy.proxy

import java.util.ArrayDeque
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/**
 * One pre-opened WebSocket per DC through the user's Cloudflare Worker (upstream pool.py
 * _CfWorkerPool), for the DCs that have no DC:IP entry. The worker is asked for
 * /apiws?dst=<DC IP>&dc=<DC>; sockets are replaced after 100 s.
 */
class CfWorkerPool(private val ctx: ProxyContext) {

    companion object {
        const val MAX_AGE_MS = 100_000L
        const val CHECK_INTERVAL_MS = 5_000L
        const val PER_DC_LIMIT = 1
        const val REFILL_BACKOFF_INITIAL_MS = 1_000L
        const val REFILL_BACKOFF_MAX_MS = 3_600_000L

        fun workerPath(fallbackDst: String, dc: Int) = "/apiws?dst=$fallbackDst&dc=$dc"
    }

    private class Idle(val ws: RawWebSocket, val created: Long, val domain: String)

    private val lock = Any()
    private val idle = HashMap<Int, ArrayDeque<Idle>>()
    private val refilling = HashMap<Int, Long>()
    private val rotating = HashSet<Int>()
    private val refillFailures = HashMap<Int, Int>()
    private val refillAfter = HashMap<Int, Long>()
    private var generation = 0L

    private val settings get() = ctx.settings
    private fun now() = System.nanoTime() / 1_000_000

    private fun target() = minOf(settings.poolSize, PER_DC_LIMIT)

    fun get(dc: Int, fallbackDst: String, workerDomains: List<String>): Pair<RawWebSocket, String>? {
        if (settings.poolSize <= 0 || workerDomains.isEmpty()) return null
        val now = now()
        var hit: Idle? = null
        val stale = ArrayList<RawWebSocket>()
        synchronized(lock) {
            val bucket = idle.getOrPut(dc) { ArrayDeque() }
            while (bucket.isNotEmpty()) {
                val e = bucket.pollFirst()!!
                if (isStale(e, now)) {
                    stale.add(e.ws)
                    continue
                }
                hit = e
                break
            }
        }
        stale.forEach { it.closeQuietly() }
        scheduleRefill(dc, fallbackDst, workerDomains)
        val h = hit
        if (h != null) {
            ctx.stats.cfPoolHits.incrementAndGet()
            ProxyLog.d { "CF worker pool hit DC$dc via ${h.domain} (age=${(now - h.created) / 1000.0}s)" }
            return h.ws to h.domain
        }
        ctx.stats.cfPoolMisses.incrementAndGet()
        return null
    }

    private fun isStale(e: Idle, now: Long) = now - e.created >= MAX_AGE_MS || e.ws.looksDead()

    private fun scheduleRefill(dc: Int, fallbackDst: String, workerDomains: List<String>) {
        if (settings.poolSize <= 0 || workerDomains.isEmpty() || ctx.stopped) return
        scheduleRotation(dc, fallbackDst, workerDomains)
        val gen: Long
        synchronized(lock) {
            if (dc in refilling || now() < (refillAfter[dc] ?: 0)) return
            gen = ++generation
            refilling[dc] = gen
        }
        try {
            ctx.executor.execute { refill(dc, fallbackDst, workerDomains.toList(), gen) }
        } catch (_: RejectedExecutionException) {
        }
    }

    private fun refill(dc: Int, fallbackDst: String, workerDomains: List<String>, gen: Long) {
        try {
            val needed = target() - synchronized(lock) { idle[dc]?.size ?: 0 }
            if (needed <= 0) return
            var connected = 0
            for (i in 0 until needed) {
                val result = connectOne(workerDomains, fallbackDst, dc) ?: break
                val adopted = synchronized(lock) {
                    if (refilling[dc] == gen && !ctx.stopped) {
                        idle.getOrPut(dc) { ArrayDeque() }.addLast(Idle(result.first, now(), result.second))
                        true
                    } else false
                }
                if (!adopted) {
                    result.first.closeQuietly()
                    return
                }
                connected++
            }
            synchronized(lock) {
                if (connected > 0) {
                    refillFailures.remove(dc)
                    refillAfter.remove(dc)
                } else {
                    val failures = (refillFailures[dc] ?: 0) + 1
                    refillFailures[dc] = failures
                    val delay = minOf(REFILL_BACKOFF_INITIAL_MS shl minOf(failures - 1, 12), REFILL_BACKOFF_MAX_MS)
                    refillAfter[dc] = now() + delay
                    ProxyLog.i("CF worker pool refill failed for DC$dc, retry in ${delay / 1000}s")
                }
            }
            ProxyLog.d { "CF worker pool refilled DC$dc: ${synchronized(lock) { idle[dc]?.size ?: 0 }} ready" }
        } finally {
            synchronized(lock) { if (refilling[dc] == gen) refilling.remove(dc) }
        }
    }

    private fun scheduleRotation(dc: Int, fallbackDst: String, workerDomains: List<String>) {
        synchronized(lock) { if (!rotating.add(dc)) return }
        scheduleRotate(dc, fallbackDst, workerDomains.toList(), CHECK_INTERVAL_MS)
    }

    private fun scheduleRotate(dc: Int, fallbackDst: String, workerDomains: List<String>, delayMs: Long) {
        try {
            ctx.scheduler.schedule({ rotate(dc, fallbackDst, workerDomains) }, maxOf(0, delayMs), TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
            synchronized(lock) { rotating.remove(dc) }
        }
    }

    private fun rotate(dc: Int, fallbackDst: String, workerDomains: List<String>) {
        if (settings.poolSize <= 0 || ctx.stopped) {
            synchronized(lock) { rotating.remove(dc) }
            return
        }
        val now = now()
        val expired = ArrayList<RawWebSocket>()
        var wakeAt = now + CHECK_INTERVAL_MS
        val below: Boolean
        synchronized(lock) {
            if (dc !in rotating) return
            val bucket = idle.getOrPut(dc) { ArrayDeque() }
            val it = bucket.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (isStale(e, now)) {
                    expired.add(e.ws)
                    it.remove()
                }
            }
            below = bucket.size < target()
            for (e in bucket) wakeAt = minOf(wakeAt, e.created + MAX_AGE_MS)
            val after = refillAfter[dc] ?: 0
            if (dc !in refilling && after > now) wakeAt = minOf(wakeAt, after)
        }
        if (expired.isNotEmpty()) {
            expired.forEach { it.closeQuietly() }
            ProxyLog.d { "CF worker pool rotated DC$dc: ${expired.size} stale" }
        }
        if (below) scheduleRefill(dc, fallbackDst, workerDomains)
        scheduleRotate(dc, fallbackDst, workerDomains, wakeAt - now())
    }

    private fun connectOne(workerDomains: List<String>, fallbackDst: String, dc: Int): Pair<RawWebSocket, String>? {
        val path = workerPath(fallbackDst, dc)
        for (domain in availableDomains(workerDomains)) {
            try {
                val ws = RawWebSocket.connect(domain, domain, timeoutMs = 8_000, path = path, secure = !settings.disableSecure)
                return ws to domain
            } catch (e: InterruptedException) {
                throw e
            } catch (e: Exception) {
                ProxyLog.d { "CF worker pool connect DC$dc via $domain for $fallbackDst failed: ${errStr(e)}" }
            }
        }
        return null
    }

    /** The worker domains, deduplicated, in random order. */
    fun availableDomains(workerDomains: List<String>): List<String> = workerDomains.distinct().shuffled()

    /** Opens the pools for the DCs that have no DC:IP entry. */
    fun warmup() {
        val workers = settings.cfproxyWorkerDomains
        val fallbacks = MtConst.DC_DEFAULT_IPS.filterKeys { it !in settings.dcRedirects }
        if (settings.poolSize <= 0 || fallbacks.isEmpty() || workers.isEmpty()) return
        for ((dc, dst) in fallbacks) scheduleRefill(dc, dst, workers)
        ProxyLog.i("CF worker pool warmup started for ${fallbacks.size} DC(s)")
    }

    fun close() {
        val all = ArrayList<RawWebSocket>()
        synchronized(lock) {
            for (b in idle.values) for (e in b) all.add(e.ws)
            idle.clear()
            refilling.clear()
            rotating.clear()
            refillFailures.clear()
            refillAfter.clear()
        }
        all.forEach { it.closeQuietly() }
    }
}
