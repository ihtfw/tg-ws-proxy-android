package org.flowseal.tgwsproxy.proxy

import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.Callable
import java.util.concurrent.CancellationException
import java.util.concurrent.ExecutionException
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicInteger

/**
 * The connectivity check (upstream ui/connectivity.py): opens a WebSocket to every DC through
 * each route the settings use (DC -> IP, the CF proxy domains, the CF workers) and reports per DC.
 * Blocking; call it off the main thread.
 *
 * A probe follows the route the proxy itself takes: the direct pool retries the handshake with
 * the fronting SNI when the plain one fails, and a media connection starts from the media domain
 * (kwsN-1). Media over HTTP/2 is not part of the check: it needs a whole okhttp session, not a
 * single WebSocket upgrade.
 */
object Connectivity {
    const val TIMEOUT_MS = 5_000

    /** A check never runs longer than this; the caller can stop it earlier with `shouldStop`. */
    const val MAX_MS = 180_000L

    /** Automatic CF domains are tried this many at a time until one serves every DC. */
    private const val AUTO_DOMAINS_PER_ROUND = 3
    private const val THREADS = 12

    /** How often a waiting check looks at the caller's stop flag. */
    private const val POLL_MS = 200L

    /** The caller (or [MAX_MS]) stopped the check. */
    class CheckCancelled : Exception("connectivity check stopped")

    enum class Route { DIRECT, CF_PROXY, CF_PROXY_AUTO, CF_WORKER }

    /**
     * One WebSocket upgrade: TCP/TLS to [host], "Host: <domain>", GET [path]. A probe walks
     * [domains] in order (the media route has two) and repeats each with the fronting SNI when
     * [fronting] is set, as the direct pool does.
     */
    data class Probe(
        val dc: Int,
        val host: String,
        val domains: List<String>,
        val path: String,
        val secure: Boolean,
        /** The media route, whose rows are marked as such in the UI. */
        val media: Boolean = false,
        /** The direct pool retries with the fronting SNI; only that route has it. */
        val fronting: Boolean = false,
    ) {
        val domain: String get() = domains.first()
    }

    sealed interface Outcome {
        /** [viaFronting]: the plain handshake failed and the fronting SNI worked. */
        data class Ok(val viaFronting: Boolean = false) : Outcome

        data object Timeout : Outcome
        data object NoResponse : Outcome
        data object HostNotFound : Outcome
        data class Http(val statusCode: Int, val statusLine: String) : Outcome
        data class Failed(val message: String) : Outcome
    }

    data class DcResult(
        val dc: Int,
        val target: String,
        val outcome: Outcome,
        val media: Boolean = false,
    ) {
        val ok: Boolean get() = outcome is Outcome.Ok
    }

    /**
     * The results for one route: one DC -> IP table, one CF domain, one worker, or (for
     * [Route.CF_PROXY_AUTO]) the automatic CF domains merged. [name] is the domain, or for the
     * automatic list the newest one that served at least one DC, if any.
     */
    data class Group(val route: Route, val name: String?, val results: List<DcResult>) {
        val okCount: Int get() = results.count { it.ok }
        val allOk: Boolean get() = results.isNotEmpty() && results.all { it.ok }
        val noneOk: Boolean get() = results.isNotEmpty() && results.none { it.ok }
    }

    /** What [check] tests for some settings. */
    data class Plan(
        val direct: List<Probe>,
        val cfProxyDomains: List<String>,
        /** The CF domains are the automatic (public) list rather than the user's own. */
        val cfAuto: Boolean,
        val workerDomains: List<String>,
        val secure: Boolean,
        /** The settings force Telegram's test DCs; the worker route then uses the test DC IPs. */
        val testDcs: Boolean = false,
    ) {
        val isEmpty: Boolean get() = direct.isEmpty() && cfProxyDomains.isEmpty() && workerDomains.isEmpty()
    }

    /**
     * @param cfDomains the CF proxy domains in use, CfProxyDomains.current(settings)
     */
    fun plan(settings: ProxySettings, cfDomains: List<String>): Plan {
        val secure = !settings.disableSecure
        // Pool size 0 turns the direct WebSocket route off; the CF proxy does not serve test DCs.
        val direct = if (settings.poolSize > 0) directProbes(settings) else emptyList()
        val cf = if (settings.fallbackCfproxy && !settings.forceTestDc) cfDomains else emptyList()
        return Plan(
            direct = direct,
            cfProxyDomains = cf,
            cfAuto = settings.cfproxyUserDomains.isEmpty(),
            // The worker serves test DCs too; Bridge.doFallback only skips the CF proxy for them.
            workerDomains = settings.cfproxyWorkerDomains,
            secure = secure,
            testDcs = settings.forceTestDc,
        )
    }

    /** The plain and the media probes of every DC the pool opens, with the domains WsPool uses. */
    fun directProbes(settings: ProxySettings): List<Probe> {
        val path = if (settings.forceTestDc) MtConst.WS_PATH_TEST else MtConst.WS_PATH
        return settings.dcRedirects.flatMap { (dc, ip) ->
            listOf(
                Probe(dc, ip, wsDomains(dc, isMedia = false), path, secure = true, fronting = true),
                Probe(dc, ip, wsDomains(dc, isMedia = true), path, secure = true, media = true, fronting = true),
            )
        }
    }

    fun cfProxyProbes(domain: String, secure: Boolean): List<Probe> = MtConst.CF_DCS.map { dc ->
        val host = "kws$dc.$domain"
        Probe(dc, host, listOf(host), MtConst.WS_PATH, secure)
    }

    /**
     * The worker is asked for its [CfWorkerPool.workerPath], the same path the proxy requests.
     * With [testDcs] the target is the test DC IP and the DCs without one are left out, as
     * Bridge.doFallback does.
     */
    fun cfWorkerProbes(domain: String, secure: Boolean, testDcs: Boolean = false): List<Probe> {
        val ips = workerIps(testDcs)
        return MtConst.CF_DCS.filter { it in ips }.map { dc ->
            Probe(dc, domain, listOf(domain), CfWorkerPool.workerPath(ips.getValue(dc), dc), secure)
        }
    }

    private fun workerIps(testDcs: Boolean): Map<Int, String> =
        if (testDcs) MtConst.DC_TEST_IPS else MtConst.DC_DEFAULT_IPS

    /**
     * Runs [plan]: the direct table, each CF domain (or the automatic list, until one domain serves
     * every DC), each worker. [onRoute] is called as each route starts.
     *
     * @param shouldStop polled between probes; when it fires, [CheckCancelled] is thrown and no
     *   further route is started, so the sockets a cancelled check does not need are never opened.
     */
    fun check(
        plan: Plan,
        probe: (Probe) -> Outcome = { Connectivity.probe(it) },
        onRoute: (Route) -> Unit = {},
        shouldStop: () -> Boolean = { false },
    ): List<Group> {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(MAX_MS)
        val stop: () -> Boolean = { shouldStop() || System.nanoTime() - deadline > 0 }
        val pool = Executors.newFixedThreadPool(THREADS, daemonThreads())
        try {
            val groups = ArrayList<Group>()
            if (plan.direct.isNotEmpty()) {
                onRoute(Route.DIRECT)
                groups += Group(Route.DIRECT, null, runAll(pool, plan.direct, probe, stop) { it.host })
            }
            if (plan.cfProxyDomains.isNotEmpty()) {
                if (plan.cfAuto) {
                    onRoute(Route.CF_PROXY_AUTO)
                    groups += checkAuto(pool, plan.cfProxyDomains, plan.secure, probe, stop)
                } else {
                    onRoute(Route.CF_PROXY)
                    val byDomain = plan.cfProxyDomains.associateWith { cfProxyProbes(it, plan.secure) }
                    val results = runAll(pool, byDomain.values.flatten(), probe, stop) { "kws${it.dc}" }
                    var i = 0
                    for ((domain, probes) in byDomain) {
                        groups += Group(Route.CF_PROXY, domain, results.subList(i, i + probes.size))
                        i += probes.size
                    }
                }
            }
            if (plan.workerDomains.isNotEmpty()) {
                onRoute(Route.CF_WORKER)
                val ips = workerIps(plan.testDcs)
                val byDomain = plan.workerDomains.associateWith {
                    cfWorkerProbes(it, plan.secure, plan.testDcs)
                }
                val results = runAll(pool, byDomain.values.flatten(), probe, stop) { ips[it.dc].orEmpty() }
                var i = 0
                for ((domain, probes) in byDomain) {
                    groups += Group(Route.CF_WORKER, domain, results.subList(i, i + probes.size))
                    i += probes.size
                }
            }
            return groups
        } finally {
            pool.shutdownNow()
        }
    }

    /** Upstream's run_cfproxy_auto_test: newest domains first, a DC counts if any domain serves it. */
    private fun checkAuto(
        pool: ExecutorService,
        domains: List<String>,
        secure: Boolean,
        probe: (Probe) -> Outcome,
        stop: () -> Boolean,
    ): Group {
        val merged = LinkedHashMap<Int, DcResult>()
        for (dc in MtConst.CF_DCS) merged[dc] = DcResult(dc, "kws$dc", Outcome.NoResponse)
        val untouched = HashSet(MtConst.CF_DCS)
        var best: String? = null
        for (round in domains.reversed().chunked(AUTO_DOMAINS_PER_ROUND)) {
            if (stop()) throw CheckCancelled()
            val probes = round.flatMap { cfProxyProbes(it, secure) }
            val results = runAll(pool, probes, probe, stop) { "kws${it.dc}" }
            for ((idx, domain) in round.withIndex()) {
                val res = results.subList(idx * MtConst.CF_DCS.size, (idx + 1) * MtConst.CF_DCS.size)
                if (res.all { it.ok }) return Group(Route.CF_PROXY_AUTO, domain, res)
                for (r in res) {
                    if (r.ok) {
                        merged[r.dc] = r
                        best = best ?: domain
                    } else if (r.dc in untouched) {
                        merged[r.dc] = r
                    }
                    untouched.remove(r.dc)
                }
            }
        }
        return Group(Route.CF_PROXY_AUTO, best, merged.values.toList())
    }

    private fun runAll(
        pool: ExecutorService,
        probes: List<Probe>,
        probe: (Probe) -> Outcome,
        stop: () -> Boolean,
        target: (Probe) -> String,
    ): List<DcResult> {
        if (stop()) throw CheckCancelled()
        val futures: List<Future<Outcome>> = probes.map { p ->
            pool.submit(Callable { safeProbe(probe, p) })
        }
        val results = ArrayList<DcResult>(probes.size)
        for ((p, f) in probes.zip(futures)) {
            results += DcResult(p.dc, target(p), await(f, stop), p.media)
        }
        return results
    }

    /** Waits for one probe, looking at [stop] so a cancelled check returns within [POLL_MS]. */
    private fun await(f: Future<Outcome>, stop: () -> Boolean): Outcome {
        while (true) {
            if (stop()) throw CheckCancelled()
            try {
                return f.get(POLL_MS, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                // Still running: look at the stop flag again.
            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                throw CheckCancelled()
            } catch (e: ExecutionException) {
                return Outcome.Failed(e.cause?.message ?: e.toString())
            } catch (e: CancellationException) {
                throw CheckCancelled()
            }
        }
    }

    private fun safeProbe(probe: (Probe) -> Outcome, p: Probe): Outcome = try {
        probe(p)
    } catch (e: Exception) {
        classify(e)
    }

    /**
     * Opens and closes one WebSocket per domain and handshake mode, in the order the proxy uses:
     * plain, then the fronting SNI when [Probe.fronting] is set. Returns the first failure when
     * none worked, so the reported reason is the one of the plain handshake.
     */
    fun probe(p: Probe, timeoutMs: Int = TIMEOUT_MS): Outcome =
        probe(p) { domain, sni -> attempt(p, domain, sni, timeoutMs) }

    /** The same, with the sockets replaced by [attempt]; a test drives it without a network. */
    fun probe(p: Probe, attempt: (domain: String, sni: String?) -> Outcome): Outcome {
        var failure: Outcome? = null
        for (domain in p.domains) {
            val plain = attempt(domain, null)
            if (plain is Outcome.Ok) return plain
            if (failure == null) failure = plain
            if (p.fronting) {
                val fronted = attempt(domain, MtConst.FRONTING_SNI)
                if (fronted is Outcome.Ok) return fronted
            }
        }
        return failure ?: Outcome.Failed("no domain to try")
    }

    private fun attempt(p: Probe, domain: String, sni: String?, timeoutMs: Int): Outcome = try {
        RawWebSocket.connect(p.host, domain, timeoutMs, p.path, sni = sni, secure = p.secure).close()
        Outcome.Ok(viaFronting = sni != null)
    } catch (e: InterruptedException) {
        Thread.currentThread().interrupt()
        Outcome.Failed("interrupted")
    } catch (e: Exception) {
        classify(e)
    }

    fun classify(e: Throwable): Outcome = when (e) {
        is WsHandshakeError ->
            if (e.statusCode == 0) Outcome.NoResponse else Outcome.Http(e.statusCode, e.statusLine)
        is SocketTimeoutException, is InterruptedIOException -> Outcome.Timeout
        is UnknownHostException -> Outcome.HostNotFound
        is java.io.EOFException -> Outcome.NoResponse
        else -> Outcome.Failed((e.message ?: e.javaClass.simpleName).take(120))
    }

    private fun daemonThreads(): ThreadFactory {
        val n = AtomicInteger()
        return ThreadFactory { r -> Thread(r, "connectivity-${n.incrementAndGet()}").apply { isDaemon = true } }
    }
}
