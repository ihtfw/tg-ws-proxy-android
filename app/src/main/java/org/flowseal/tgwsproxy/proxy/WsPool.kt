package org.flowseal.tgwsproxy.proxy

import java.util.ArrayDeque
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorCompletionService
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.TimeUnit

/**
 * Pre-opened WebSockets to each configured DC (upstream pool.py _WsPool). A client is served only
 * from the pool: a miss goes to the fallbacks while the pool refills in the background. Idle
 * sockets are replaced after two minutes, a failing refill backs off from 1 s up to an hour, and
 * each connection is tried directly and "fronted" (another SNI), the last mode that worked first.
 */
class WsPool(private val ctx: ProxyContext) {

    companion object {
        const val MAX_AGE_MS = 120_000L
        const val CHECK_INTERVAL_MS = 5_000L
        const val REFILL_BACKOFF_INITIAL_MS = 1_000L
        const val REFILL_BACKOFF_MAX_MS = 3_600_000L
    }

    private data class Key(val dc: Int, val isMedia: Boolean, val isTest: Boolean) {
        override fun toString() = dcTag(dc, isMedia, isTest)
    }

    private class Idle(val ws: RawWebSocket, val created: Long)

    private val lock = Any()
    private val idle = HashMap<Key, ArrayDeque<Idle>>()
    /** Refill generation per key; a refill whose generation is gone after reset() closes what it opened. */
    private val refilling = HashMap<Key, Long>()
    private val rotating = HashSet<Key>()
    private val refillFailures = HashMap<Key, Int>()
    private val refillAfter = HashMap<Key, Long>()
    private var generation = 0L

    @Volatile var tryFrontingFirst = false

    private val settings get() = ctx.settings

    private fun now() = System.nanoTime() / 1_000_000

    fun get(dc: Int, isMedia: Boolean, isTest: Boolean = false): RawWebSocket? {
        val targetIp = settings.dcRedirects[dc]
        if (targetIp == null || settings.poolSize <= 0) return null
        val key = Key(dc, isMedia, isTest)
        val now = now()
        var hit: Idle? = null
        val stale = ArrayList<RawWebSocket>()
        synchronized(lock) {
            val bucket = idle.getOrPut(key) { ArrayDeque() }
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
        val h = hit
        if (h != null) {
            ctx.stats.poolHits.incrementAndGet()
            ProxyLog.d { "WS pool hit $key (age=${(now - h.created) / 1000.0}s, left=${size(key)})" }
            scheduleRefill(key, targetIp)
            return h.ws
        }
        ctx.stats.poolMisses.incrementAndGet()
        scheduleRefill(key, targetIp)
        return null
    }

    private fun size(key: Key): Int = synchronized(lock) { idle[key]?.size ?: 0 }

    private fun isStale(e: Idle, now: Long) = now - e.created >= MAX_AGE_MS || e.ws.looksDead()

    private fun scheduleRefill(key: Key, targetIp: String) {
        if (settings.poolSize <= 0 || ctx.stopped) return
        scheduleRotation(key, targetIp)
        val gen: Long
        synchronized(lock) {
            if (key in refilling || now() < (refillAfter[key] ?: 0)) return
            gen = ++generation
            refilling[key] = gen
        }
        submit { refill(key, targetIp, gen) }
    }

    private fun submit(task: () -> Unit) {
        try {
            ctx.executor.execute(task)
        } catch (_: RejectedExecutionException) {
        }
    }

    private fun refill(key: Key, targetIp: String, gen: Long) {
        val futures = ArrayList<Future<RawWebSocket?>>()
        try {
            val needed = settings.poolSize - size(key)
            if (needed <= 0) return
            val path = if (key.isTest) MtConst.WS_PATH_TEST else MtConst.WS_PATH
            val domains = wsDomains(key.dc, key.isMedia)
            val completion = ExecutorCompletionService<RawWebSocket?>(ctx.executor)
            repeat(needed) { futures.add(completion.submit(Callable { connectOne(targetIp, domains, path) })) }
            var connected = 0
            repeat(futures.size) {
                val ws = try {
                    completion.take().get()
                } catch (e: InterruptedException) {
                    throw e
                } catch (e: Exception) {
                    ProxyLog.d { "WS pool connect failed: ${errStr(e)}" }
                    null
                }
                if (ws != null) {
                    val adopted = synchronized(lock) {
                        if (refilling[key] == gen && !ctx.stopped) {
                            idle.getOrPut(key) { ArrayDeque() }.addLast(Idle(ws, now()))
                            true
                        } else false
                    }
                    if (adopted) connected++ else ws.closeQuietly()
                }
            }
            synchronized(lock) {
                if (connected > 0) {
                    refillFailures.remove(key)
                    refillAfter.remove(key)
                } else if (refilling[key] == gen) {
                    val failures = (refillFailures[key] ?: 0) + 1
                    refillFailures[key] = failures
                    val delay = minOf(REFILL_BACKOFF_INITIAL_MS shl minOf(failures - 1, 12), REFILL_BACKOFF_MAX_MS)
                    refillAfter[key] = now() + delay
                    ProxyLog.i("WS pool refill failed for $key, retry in ${delay / 1000}s")
                }
            }
            ProxyLog.d { "WS pool refilled $key: ${size(key)} ready" }
        } catch (_: InterruptedException) {
            for (f in futures) {
                f.cancel(true)
                if (f.isDone && !f.isCancelled) runCatching { f.get() }.getOrNull().closeQuietly()
            }
        } finally {
            synchronized(lock) { if (refilling[key] == gen) refilling.remove(key) }
        }
    }

    private fun scheduleRotation(key: Key, targetIp: String) {
        synchronized(lock) {
            if (!rotating.add(key)) return
        }
        scheduleRotate(key, targetIp, CHECK_INTERVAL_MS)
    }

    private fun scheduleRotate(key: Key, targetIp: String, delayMs: Long) {
        try {
            ctx.scheduler.schedule({ rotate(key, targetIp) }, maxOf(0, delayMs), TimeUnit.MILLISECONDS)
        } catch (_: RejectedExecutionException) {
            synchronized(lock) { rotating.remove(key) }
        }
    }

    /** Drops stale sockets, tops the bucket up and sleeps until the next socket expires. */
    private fun rotate(key: Key, targetIp: String) {
        if (settings.poolSize <= 0 || ctx.stopped) {
            synchronized(lock) { rotating.remove(key) }
            return
        }
        val now = now()
        val expired = ArrayList<RawWebSocket>()
        var wakeAt = now + CHECK_INTERVAL_MS
        var below: Boolean
        synchronized(lock) {
            if (key !in rotating) return
            val bucket = idle.getOrPut(key) { ArrayDeque() }
            val it = bucket.iterator()
            while (it.hasNext()) {
                val e = it.next()
                if (isStale(e, now)) {
                    expired.add(e.ws)
                    it.remove()
                }
            }
            below = bucket.size < settings.poolSize
            for (e in bucket) wakeAt = minOf(wakeAt, e.created + MAX_AGE_MS)
            val after = refillAfter[key] ?: 0
            if (key !in refilling && after > now) wakeAt = minOf(wakeAt, after)
        }
        if (expired.isNotEmpty()) {
            submit { expired.forEach { it.closeQuietly() } }
            ProxyLog.d { "WS pool rotated $key: ${expired.size} stale, ${size(key)} ready" }
        }
        if (below) scheduleRefill(key, targetIp)
        scheduleRotate(key, targetIp, wakeAt - now())
    }

    private fun connectOne(targetIp: String, domains: List<String>, path: String): RawWebSocket? {
        for (domain in domains) {
            val modes = if (tryFrontingFirst) listOf(true, false) else listOf(false, true)
            for (fronted in modes) {
                val ws = try {
                    RawWebSocket.connect(
                        targetIp, domain,
                        timeoutMs = if (fronted) 7_000 else 8_000,
                        path = path,
                        sni = if (fronted) MtConst.FRONTING_SNI else null,
                    )
                } catch (e: InterruptedException) {
                    throw e
                } catch (e: Exception) {
                    ctx.stats.wsErrors.incrementAndGet()
                    ProxyLog.d { "WS pool connect $domain$path via $targetIp (fronting=$fronted): ${errStr(e)}" }
                    continue
                }
                tryFrontingFirst = fronted
                if (fronted) ctx.stats.connectionsFronting.incrementAndGet()
                ProxyLog.d { "WS pool connected $domain$path via $targetIp (fronting=$fronted)" }
                return ws
            }
        }
        return null
    }

    fun warmup() {
        for ((dc, targetIp) in settings.dcRedirects) {
            for (isMedia in listOf(false, true)) {
                scheduleRefill(Key(dc, isMedia, settings.forceTestDc), targetIp)
            }
        }
        ProxyLog.i("WS pool warmup started for ${settings.dcRedirects.size} DC(s)")
    }

    fun close() {
        val all = ArrayList<RawWebSocket>()
        synchronized(lock) {
            for (bucket in idle.values) for (e in bucket) all.add(e.ws)
            idle.clear()
            refilling.clear()
            rotating.clear()
            refillFailures.clear()
            refillAfter.clear()
            tryFrontingFirst = false
        }
        all.forEach { it.closeQuietly() }
    }
}
