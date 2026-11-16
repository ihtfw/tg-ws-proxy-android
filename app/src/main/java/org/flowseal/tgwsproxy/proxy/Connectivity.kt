package org.flowseal.tgwsproxy.proxy

import java.io.InterruptedIOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger

/**
 * The connectivity check (upstream ui/connectivity.py): opens a WebSocket to every DC through
 * each route the settings use (DC -> IP, the CF proxy domains, the CF workers) and reports per DC.
 * Blocking; call it off the main thread.
 */
object Connectivity {
    const val TIMEOUT_MS = 5_000

    /** Automatic CF domains are tried this many at a time until one serves every DC. */
    private const val AUTO_DOMAINS_PER_ROUND = 3
    private const val THREADS = 12

    enum class Route { DIRECT, CF_PROXY, CF_PROXY_AUTO, CF_WORKER }

    /** One WebSocket upgrade: TCP/TLS to [host], "Host: [domain]", GET [path]. */
    data class Probe(
        val dc: Int,
        val host: String,
        val domain: String,
        val path: String,
        val secure: Boolean,
    )

    sealed interface Outcome {
        data object Ok : Outcome
        data object Timeout : Outcome
        data object NoResponse : Outcome
        data object HostNotFound : Outcome
        data class Http(val statusCode: Int, val statusLine: String) : Outcome
        data class Failed(val message: String) : Outcome
    }

    data class DcResult(val dc: Int, val target: String, val outcome: Outcome) {
        val ok: Boolean get() = outcome == Outcome.Ok
    }

    /**
     * The results for one route: one DC -> IP table, one CF domain, one worker, or (for
     * [Route.CF_PROXY_AUTO]) the automatic CF domains merged, without naming them.
     * [name] is the domain, or for the automatic list the one that served every DC, if any.
     */
    data class Group(val route: Route, val name: String?, val results: List<DcResult>) {
        val okCount: Int get() = results.count { it.ok }
        val allOk: Boolean get() = results.isNotEmpty() && results.all { it.ok }
        val noneOk: Boolean get() = results.none { it.ok }
    }

    /** What [check] tests for some settings. */
    data class Plan(
        val direct: List<Probe>,
        val cfProxyDomains: List<String>,
        /** The CF domains are the automatic (public) list rather than the user's own. */
        val cfAuto: Boolean,
        val workerDomains: List<String>,
        val secure: Boolean,
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
            workerDomains = settings.cfproxyWorkerDomains,
            secure = secure,
        )
    }

    fun directProbes(settings: ProxySettings): List<Probe> {
        val path = if (settings.forceTestDc) MtConst.WS_PATH_TEST else MtConst.WS_PATH
        return settings.dcRedirects.map { (dc, ip) ->
            Probe(dc, ip, wsDomains(dc, isMedia = false).first(), path, secure = true)
        }
    }

    fun cfProxyProbes(domain: String, secure: Boolean): List<Probe> = MtConst.CF_DCS.map { dc ->
        val host = "kws$dc.$domain"
        Probe(dc, host, host, MtConst.WS_PATH, secure)
    }

    fun cfWorkerProbes(domain: String, secure: Boolean): List<Probe> = MtConst.CF_DCS.map { dc ->
        val dst = MtConst.DC_DEFAULT_IPS.getValue(dc)
        Probe(dc, domain, domain, "${MtConst.WS_PATH}?dst=$dst&dc=$dc&media=0", secure)
    }

    /**
     * Runs [plan]: the direct table, each CF domain (or the automatic list, until one domain serves
     * every DC), each worker. [onRoute] is called as each route starts.
     */
    fun check(
        plan: Plan,
        probe: (Probe) -> Outcome = { Connectivity.probe(it) },
        onRoute: (Route) -> Unit = {},
    ): List<Group> {
        val pool = Executors.newFixedThreadPool(THREADS, daemonThreads())
        try {
            val groups = ArrayList<Group>()
            if (plan.direct.isNotEmpty()) {
                onRoute(Route.DIRECT)
                groups += Group(Route.DIRECT, null, runAll(pool, plan.direct, probe) { it.host })
            }
            if (plan.cfProxyDomains.isNotEmpty()) {
                if (plan.cfAuto) {
                    onRoute(Route.CF_PROXY_AUTO)
                    groups += checkAuto(pool, plan.cfProxyDomains, plan.secure, probe)
                } else {
                    onRoute(Route.CF_PROXY)
                    val byDomain = plan.cfProxyDomains.associateWith { cfProxyProbes(it, plan.secure) }
                    val results = runAll(pool, byDomain.values.flatten(), probe) { "kws${it.dc}" }
                    var i = 0
                    for ((domain, probes) in byDomain) {
                        groups += Group(Route.CF_PROXY, domain, results.subList(i, i + probes.size))
                        i += probes.size
                    }
                }
            }
            if (plan.workerDomains.isNotEmpty()) {
                onRoute(Route.CF_WORKER)
                val byDomain = plan.workerDomains.associateWith { cfWorkerProbes(it, plan.secure) }
                val results = runAll(pool, byDomain.values.flatten(), probe) { MtConst.DC_DEFAULT_IPS.getValue(it.dc) }
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
    ): Group {
        val merged = LinkedHashMap<Int, DcResult>()
        for (dc in MtConst.CF_DCS) merged[dc] = DcResult(dc, "kws$dc", Outcome.NoResponse)
        val untouched = HashSet(MtConst.CF_DCS)
        var best: String? = null
        for (round in domains.reversed().chunked(AUTO_DOMAINS_PER_ROUND)) {
            val probes = round.flatMap { cfProxyProbes(it, secure) }
            val results = runAll(pool, probes, probe) { "kws${it.dc}" }
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
        target: (Probe) -> String,
    ): List<DcResult> {
        val futures: List<Future<Outcome>> = probes.map { p ->
            pool.submit(Callable { safeProbe(probe, p) })
        }
        return probes.zip(futures).map { (p, f) ->
            val outcome = try {
                f.get()
            } catch (e: Exception) {
                Outcome.Failed(e.cause?.message ?: e.toString())
            }
            DcResult(p.dc, target(p), outcome)
        }
    }

    private fun safeProbe(probe: (Probe) -> Outcome, p: Probe): Outcome = try {
        probe(p)
    } catch (e: Exception) {
        classify(e)
    }

    /** Opens and closes one WebSocket. */
    fun probe(p: Probe, timeoutMs: Int = TIMEOUT_MS): Outcome = try {
        RawWebSocket.connect(p.host, p.domain, timeoutMs, p.path, sni = null, secure = p.secure).close()
        Outcome.Ok
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
