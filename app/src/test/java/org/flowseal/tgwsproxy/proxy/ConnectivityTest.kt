package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

class ConnectivityTest {

    private val base = ProxySettings(secretHex = "0123456789abcdef0123456789abcdef")

    @Test
    fun planFollowsSettings() {
        val plan = Connectivity.plan(base, listOf("a.example", "b.example"))
        // Two probes per DC: the plain route and the media route.
        assertEquals(listOf(2, 2, 4, 4), plan.direct.map { it.dc })
        assertEquals("149.154.167.220", plan.direct[0].host)
        assertEquals("kws2.web.telegram.org", plan.direct[0].domain)
        assertEquals("/apiws", plan.direct[0].path)
        assertTrue(plan.direct.all { it.secure })
        assertTrue(plan.direct.all { it.fronting })
        assertFalse(plan.direct[0].media)
        // A media connection starts from the media domain, as WsPool does.
        assertTrue(plan.direct[1].media)
        assertEquals(listOf("kws2-1.web.telegram.org", "kws2.web.telegram.org"), plan.direct[1].domains)
        assertEquals(listOf("a.example", "b.example"), plan.cfProxyDomains)
        assertTrue(plan.cfAuto)
        assertTrue(plan.workerDomains.isEmpty())
        assertTrue(plan.secure)
        assertFalse(plan.testDcs)

        val off = Connectivity.plan(base.copy(fallbackCfproxy = false, poolSize = 0), listOf("a.example"))
        assertTrue(off.isEmpty)

        val own = Connectivity.plan(
            base.copy(
                cfproxyUserDomains = listOf("mine.example"),
                cfproxyWorkerDomains = listOf("w.workers.dev"),
                disableSecure = true,
            ),
            listOf("mine.example"),
        )
        assertFalse(own.cfAuto)
        assertFalse(own.secure)
        assertEquals(listOf("w.workers.dev"), own.workerDomains)

        val test = Connectivity.plan(base.copy(forceTestDc = true), listOf("a.example"))
        assertEquals("/apiws_test", test.direct[0].path)
        assertTrue(test.cfProxyDomains.isEmpty())
        assertTrue(test.testDcs)
    }

    @Test
    fun probesMatchUpstream() {
        val cf = Connectivity.cfProxyProbes("example.com", secure = true)
        assertEquals(listOf(1, 2, 3, 4, 5, 203), cf.map { it.dc })
        assertEquals("kws203.example.com", cf.last().host)
        assertEquals("kws203.example.com", cf.last().domain)

        val worker = Connectivity.cfWorkerProbes("w.workers.dev", secure = false)
        assertEquals("w.workers.dev", worker[0].host)
        // The probe asks for the very path the proxy asks for.
        assertEquals(CfWorkerPool.workerPath("149.154.175.50", 1), worker[0].path)
        assertEquals("/apiws?dst=149.154.175.50&dc=1", worker[0].path)
        assertFalse(worker[0].secure)

        // Forced test DCs: only the DCs that have a test IP, and the worker is asked for that IP.
        val test = Connectivity.cfWorkerProbes("w.workers.dev", secure = true, testDcs = true)
        assertEquals(listOf(1, 2, 3), test.map { it.dc })
        assertEquals("/apiws?dst=149.154.167.40&dc=2", test[1].path)
    }

    @Test
    fun checkGroupsResultsPerRoute() {
        val plan = Connectivity.plan(
            base.copy(
                cfproxyUserDomains = listOf("good.example", "bad.example"),
                cfproxyWorkerDomains = listOf("w.workers.dev"),
            ),
            listOf("good.example", "bad.example"),
        )
        val routes = Collections.synchronizedList(ArrayList<Connectivity.Route>())
        val groups = Connectivity.check(plan, probe = { p ->
            when {
                p.host == "149.154.167.220" && p.dc == 4 -> throw SocketTimeoutException()
                p.host.endsWith("bad.example") -> Connectivity.Outcome.Http(403, "HTTP/1.1 403 Forbidden")
                p.host == "w.workers.dev" && p.dc == 203 -> throw UnknownHostException("w.workers.dev")
                else -> Connectivity.Outcome.Ok()
            }
        }, onRoute = { routes += it })

        assertEquals(
            listOf(Connectivity.Route.DIRECT, Connectivity.Route.CF_PROXY, Connectivity.Route.CF_WORKER),
            routes,
        )
        assertEquals(
            listOf(
                Connectivity.Route.DIRECT, Connectivity.Route.CF_PROXY,
                Connectivity.Route.CF_PROXY, Connectivity.Route.CF_WORKER,
            ),
            groups.map { it.route },
        )
        val direct = groups[0]
        assertEquals(2, direct.okCount)
        assertEquals(Connectivity.Outcome.Timeout, direct.results[2].outcome)
        assertEquals("good.example", groups[1].name)
        assertTrue(groups[1].allOk)
        assertTrue(groups[2].noneOk)
        assertEquals(Connectivity.Outcome.Http(403, "HTTP/1.1 403 Forbidden"), groups[2].results[0].outcome)
        assertEquals(5, groups[3].okCount)
        assertEquals(Connectivity.Outcome.HostNotFound, groups[3].results.last().outcome)
    }

    @Test
    fun autoDomainsStopAtTheFirstThatServesEveryDc() {
        val domains = (1..10).map { "d$it.example" }
        val tried = Collections.synchronizedSet(HashSet<String>())
        val plan = Connectivity.plan(base.copy(poolSize = 0), domains)
        val groups = Connectivity.check(plan, probe = { p ->
            val domain = p.host.substringAfter('.')
            tried += domain
            if (domain == "d8.example" || (domain == "d10.example" && p.dc == 1)) Connectivity.Outcome.Ok()
            else Connectivity.Outcome.Failed("refused")
        })
        assertEquals(1, groups.size)
        val auto = groups[0]
        assertEquals(Connectivity.Route.CF_PROXY_AUTO, auto.route)
        // The domain that served every DC is named, so the screen can show it.
        assertEquals("d8.example", auto.name)
        assertTrue(auto.allOk)
        // Newest first, three at a time: d10, d9 and d8 are enough.
        assertEquals(setOf("d10.example", "d9.example", "d8.example"), tried.toSet())
    }

    @Test
    fun autoDomainsMergePerDc() {
        val plan = Connectivity.plan(base.copy(poolSize = 0), listOf("a.example", "b.example"))
        val auto = Connectivity.check(plan, probe = { p ->
            if (p.host == "kws2.a.example" || p.host == "kws4.b.example") Connectivity.Outcome.Ok()
            else Connectivity.Outcome.NoResponse
        }).single()
        assertEquals(2, auto.okCount)
        assertEquals(listOf(2, 4), auto.results.filter { it.ok }.map { it.dc })

        val none = Connectivity.check(plan, probe = { Connectivity.Outcome.Timeout }).single()
        assertTrue(none.noneOk)
        assertNull(none.name)
    }

    @Test
    fun probeWalksTheDomainsAndRetriesWithFronting() {
        val probe = Connectivity.Probe(
            2,
            "149.154.167.220",
            listOf("kws2-1.web.telegram.org", "kws2.web.telegram.org"),
            "/apiws",
            secure = true,
            media = true,
            fronting = true,
        )
        val tries = Collections.synchronizedList(ArrayList<String>())
        val out = Connectivity.probe(probe) { domain, sni ->
            tries += "$domain sni=$sni"
            when {
                domain == "kws2-1.web.telegram.org" -> Connectivity.Outcome.Timeout
                sni == null -> Connectivity.Outcome.Http(403, "HTTP/1.1 403 Forbidden")
                else -> Connectivity.Outcome.Ok(viaFronting = true)
            }
        }
        assertEquals(
            listOf(
                "kws2-1.web.telegram.org sni=null",
                "kws2-1.web.telegram.org sni=${MtConst.FRONTING_SNI}",
                "kws2.web.telegram.org sni=null",
                "kws2.web.telegram.org sni=${MtConst.FRONTING_SNI}",
            ),
            tries,
        )
        assertEquals(Connectivity.Outcome.Ok(viaFronting = true), out)
    }

    @Test
    fun probeWithoutFrontingTriesThePlainHandshakeOnly() {
        val probe = Connectivity.Probe(1, "w.workers.dev", listOf("w.workers.dev"), "/apiws", secure = true)
        val tries = ArrayList<String?>()
        val out = Connectivity.probe(probe) { _, sni ->
            tries += sni
            Connectivity.Outcome.Http(522, "HTTP/1.1 522")
        }
        assertEquals(listOf<String?>(null), tries)
        assertEquals(Connectivity.Outcome.Http(522, "HTTP/1.1 522"), out)
    }

    @Test
    fun probeReportsTheFirstFailureWhenNothingWorks() {
        val probe = Connectivity.Probe(
            2, "ip", listOf("a.example", "b.example"), "/apiws", secure = true, fronting = true,
        )
        val out = Connectivity.probe(probe) { domain, sni ->
            if (domain == "a.example" && sni == null) Connectivity.Outcome.Timeout
            else Connectivity.Outcome.Http(403, "HTTP/1.1 403")
        }
        assertEquals(Connectivity.Outcome.Timeout, out)
    }

    @Test
    fun aCancelledCheckStopsEarly() {
        val plan = Connectivity.plan(base.copy(cfproxyUserDomains = listOf("good.example")), listOf("good.example"))
        val calls = AtomicInteger()
        try {
            Connectivity.check(
                plan,
                probe = {
                    calls.incrementAndGet()
                    Thread.sleep(5)
                    Connectivity.Outcome.Ok()
                },
                shouldStop = { calls.get() > 1 },
            )
            fail("the check kept running after shouldStop")
        } catch (_: Connectivity.CheckCancelled) {
        }
    }

    @Test
    fun anEmptyGroupIsNeitherWorkingNorBroken() {
        val group = Connectivity.Group(Connectivity.Route.DIRECT, null, emptyList())
        assertFalse(group.allOk)
        assertFalse(group.noneOk)
        assertEquals(0, group.okCount)
    }

    @Test
    fun classify() {
        assertEquals(Connectivity.Outcome.NoResponse, Connectivity.classify(WsHandshakeError(0, "empty response")))
        assertEquals(
            Connectivity.Outcome.Http(302, "HTTP/1.1 302 Found"),
            Connectivity.classify(WsHandshakeError(302, "HTTP/1.1 302 Found")),
        )
        assertEquals(Connectivity.Outcome.Timeout, Connectivity.classify(SocketTimeoutException("connect timed out")))
        assertEquals(Connectivity.Outcome.HostNotFound, Connectivity.classify(UnknownHostException("x")))
        assertEquals(
            Connectivity.Outcome.Failed("Connection refused"),
            Connectivity.classify(java.net.ConnectException("Connection refused")),
        )
    }
}
