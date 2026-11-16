package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CfProxyTest {

    @Test
    fun decodesLikeUpstream() {
        // upstream: [_dd(d) for d in _CFPROXY_ENC][:3]
        assertEquals(listOf("pclead.co.uk", "offshor.co.uk", "cakeisalie.co.uk"), CfProxyDomains.DEFAULT_DOMAINS.take(3))
        assertEquals(20, CfProxyDomains.DEFAULT_DOMAINS.size)
        assertEquals("plain.org", CfProxyDomains.decode("plain.org"))
    }

    @Test
    fun parsesAndNormalizesTheList() {
        val list = CfProxyDomains.parseList("# comment\nvirkgj.com\n\n  vmmzovy.com \n")
        assertEquals(listOf("pclead.co.uk", "offshor.co.uk"), list)
        assertEquals(
            listOf("a.example.com"),
            CfProxyDomains.normalize(listOf("A.example.com", "a.example.com", "-bad.com", "nodot", "x.123", ".a.com"))
        )
        assertTrue(CfProxyDomains.isValidDomain("kws2.example.co.uk"))
        assertFalse(CfProxyDomains.isValidDomain("exa mple.com"))
    }

    @Test
    fun userDomainsWin() {
        val s = ProxySettings(cfproxyUserDomains = listOf("my.example.com"))
        assertEquals(listOf("my.example.com"), CfProxyDomains.current(s))
        assertEquals(CfProxyDomains.latest, CfProxyDomains.current(ProxySettings()))
    }

    @Test
    fun balancerKeepsTheWorkingDomainFirst() {
        val b = Balancer()
        b.updateDomainsList(listOf("a.com", "b.com", "c.com"))
        val first = b.domainsForDc(2)
        assertEquals(3, first.size)
        assertEquals(setOf("a.com", "b.com", "c.com"), first.toSet())
        val other = first.last()
        assertTrue(b.updateDomainForDc(2, other))
        assertFalse(b.updateDomainForDc(2, other))
        assertEquals(other, b.domainsForDc(2).first())
        // the same list again keeps the choice
        b.updateDomainsList(listOf("c.com", "b.com", "a.com"))
        assertEquals(other, b.domainsForDc(2).first())
    }

    @Test
    fun workerPath() {
        assertEquals("/apiws?dst=149.154.175.50&dc=1", CfWorkerPool.workerPath("149.154.175.50", 1))
    }
}
