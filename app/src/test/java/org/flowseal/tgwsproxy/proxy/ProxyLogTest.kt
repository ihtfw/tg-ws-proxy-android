package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ProxyLogTest {

    private val secret = "0123456789abcdef0123456789abcdef"

    @Test
    fun keepsTelegramNamesLogFilesAndClassNames() {
        assertEquals("kws2.web.telegram.org", ProxyLog.censor("kws2.web.telegram.org"))
        assertEquals("proxy.log", ProxyLog.censor("proxy.log"))
        assertEquals("java.net.SocketTimeoutException", ProxyLog.censor("java.net.SocketTimeoutException"))
    }

    @Test
    fun masksOtherDomains() {
        assertEquals("kw**.exa****.com", ProxyLog.censor("kws2.example.com"))
    }

    /** The banner is logged on every start, and a log is meant to be shared. */
    @Test
    fun masksTheSecretOfTheStartupBanner() {
        val out = ProxyLog.censor("  Secret:        $secret")
        assertFalse(out.contains(secret))
        assertEquals("  Secret:        01234567****", out)
    }

    @Test
    fun masksTheSecretOfATgLink() {
        val out = ProxyLog.censor("    tg://proxy?server=192.168.1.5&port=1443&secret=dd$secret")
        assertFalse(out.contains(secret))
        assertEquals("    tg://proxy?server=192.168.1.5&port=1443&secret=dd012345****", out)
    }

    @Test
    fun masksTheSecretOfAFakeTlsLink() {
        val out = ProxyLog.censor("secret=ee$secret${"6d6173636f742e7275"}")
        assertFalse(out.contains(secret))
        assertEquals("secret=ee012345****", out)
    }

    @Test
    fun censoringTwiceChangesNothing() {
        val line = "kws2.example.com secret=dd$secret"
        val once = ProxyLog.censor(line)
        assertEquals(once, ProxyLog.censor(once))
    }
}
