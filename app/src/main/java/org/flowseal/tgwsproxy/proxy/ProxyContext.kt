package org.flowseal.tgwsproxy.proxy

import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The state one running proxy shares between its parts, in place of upstream's module globals:
 * settings, counters, the CF domain balancer and the threads.
 */
class ProxyContext(val settings: ProxySettings) {
    val stats = Stats()
    val balancer = Balancer()

    @Volatile var stopped = false
        private set

    private val threadNo = AtomicInteger()

    /** Connection handlers, bridges and pool refills; daemon threads, created as needed. */
    val executor: ExecutorService = Executors.newCachedThreadPool { r ->
        Thread(r, "tgws-${threadNo.incrementAndGet()}").apply { isDaemon = true }
    }

    /** Pool rotation, the CF domain refresh and the stats line. */
    val scheduler: ScheduledExecutorService = Executors.newScheduledThreadPool(2) { r ->
        Thread(r, "tgws-sched-${threadNo.incrementAndGet()}").apply { isDaemon = true }
    }

    fun shutdown() {
        stopped = true
        scheduler.shutdownNow()
        executor.shutdownNow()
        try {
            executor.awaitTermination(2, TimeUnit.SECONDS)
        } catch (_: InterruptedException) {
        }
    }
}

/** Closes without throwing. */
fun AutoCloseable?.closeQuietly() {
    try {
        this?.close()
    } catch (_: Throwable) {
    }
}
