package org.flowseal.tgwsproxy.service

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.net.BindException

class SettingsDraftTest {

    private val secret = "0123456789abcdef0123456789ABCDEF"
    private val valid = SettingsDraft(secret = secret)

    private fun expectError(draft: SettingsDraft, field: ConfigField, kind: ConfigError.Kind, entry: String = "") {
        try {
            draft.toProxySettings()
            fail("expected $field $kind")
        } catch (e: ConfigException) {
            assertEquals(ConfigError(field, kind, entry), e.error)
        }
    }

    @Test
    fun defaultsMatchUpstream() {
        val s = valid.toProxySettings()
        assertEquals("127.0.0.1", s.host)
        assertEquals(1443, s.port)
        assertEquals(mapOf(2 to "149.154.167.220", 4 to "149.154.167.220"), s.dcRedirects)
        assertEquals(4, s.poolSize)
        assertEquals(256 * 1024, s.bufferSize)
        assertFalse(s.forceTestDc)
        assertEquals(secret.lowercase(), s.secretHex)
        assertEquals("tg://proxy?server=127.0.0.1&port=1443&secret=dd${secret.lowercase()}", s.proxyLink())
    }

    @Test
    fun listenAllSwitchesHost() {
        assertFalse(valid.listenAll)
        val all = valid.withListenAll(true)
        assertTrue(all.listenAll)
        assertEquals("0.0.0.0", all.toProxySettings().host)
        assertEquals("127.0.0.1", all.withListenAll(false).host)
    }

    @Test
    fun badPort() {
        expectError(valid.copy(port = ""), ConfigField.PORT, ConfigError.Kind.BAD_PORT)
        expectError(valid.copy(port = "0"), ConfigField.PORT, ConfigError.Kind.BAD_PORT)
        expectError(valid.copy(port = "65536"), ConfigField.PORT, ConfigError.Kind.BAD_PORT)
        assertEquals(65535, valid.copy(port = " 65535 ").toProxySettings().port)
    }

    @Test
    fun badSecret() {
        expectError(valid.copy(secret = ""), ConfigField.SECRET, ConfigError.Kind.SECRET_LENGTH)
        expectError(valid.copy(secret = secret.drop(1)), ConfigField.SECRET, ConfigError.Kind.SECRET_LENGTH)
        expectError(valid.copy(secret = "g" + secret.drop(1)), ConfigField.SECRET, ConfigError.Kind.SECRET_HEX)
    }

    @Test
    fun badDcEntryIsNamed() {
        expectError(
            valid.copy(dcIps = "2:149.154.167.220\nnonsense"),
            ConfigField.DC_IPS, ConfigError.Kind.DC_FORMAT, "nonsense",
        )
        expectError(
            valid.copy(dcIps = "2:149.154.167.220\n4:149.154.167.300"),
            ConfigField.DC_IPS, ConfigError.Kind.DC_INVALID, "4:149.154.167.300",
        )
        expectError(valid.copy(dcIps = "x:1.2.3.4"), ConfigField.DC_IPS, ConfigError.Kind.DC_INVALID, "x:1.2.3.4")
    }

    @Test
    fun dcRulesIgnoreBlankLinesAndMayBeEmpty() {
        val s = valid.copy(dcIps = "\n 1:149.154.175.50 \n\n").toProxySettings()
        assertEquals(mapOf(1 to "149.154.175.50"), s.dcRedirects)
        assertEquals(emptyMap<Int, String>(), valid.copy(dcIps = "").toProxySettings().dcRedirects)
    }

    @Test
    fun numberLimits() {
        assertEquals(0, valid.copy(poolSize = "0").toProxySettings().poolSize)
        expectError(valid.copy(poolSize = "65"), ConfigField.POOL_SIZE, ConfigError.Kind.BAD_POOL_SIZE)
        expectError(valid.copy(bufKb = "3"), ConfigField.BUFFER, ConfigError.Kind.BAD_BUFFER)
        expectError(valid.copy(bufKb = "abc"), ConfigField.BUFFER, ConfigError.Kind.BAD_BUFFER)
    }

    @Test
    fun errorsListEveryBadField() {
        val fields = valid.copy(host = "localhost", port = "x", secret = "1", dcIps = "bad").errors().map { it.field }
        assertEquals(listOf(ConfigField.HOST, ConfigField.PORT, ConfigField.SECRET, ConfigField.DC_IPS), fields)
    }

    @Test
    fun cloudflareDefaultsAndDomains() {
        val s = valid.toProxySettings()
        assertTrue(s.fallbackCfproxy)
        assertEquals(emptyList<String>(), s.cfproxyUserDomains)
        assertEquals(emptyList<String>(), s.cfproxyWorkerDomains)
        assertFalse(s.disableSecure)

        val custom = valid.copy(
            cfUserDomainEnabled = true,
            cfUserDomains = "a.example.com, b.example.org;A.example.com",
            cfWorkerEnabled = true,
            cfWorkerDomains = "name.account.workers.dev",
            noSecure = true,
        ).toProxySettings()
        assertEquals(listOf("a.example.com", "b.example.org"), custom.cfproxyUserDomains)
        assertEquals(listOf("name.account.workers.dev"), custom.cfproxyWorkerDomains)
        assertTrue(custom.disableSecure)
    }

    @Test
    fun h2Media() {
        assertTrue(valid.toProxySettings().cfproxyH2Media)
        assertTrue(valid.toProxySettings().h2Enabled)
        assertFalse(valid.copy(h2Media = false).toProxySettings().cfproxyH2Media)
        assertTrue(valid.h2Available)
        assertFalse(valid.copy(noSecure = true).h2Available)
        assertFalse(valid.copy(cfproxy = false).h2Available)
        assertFalse(valid.copy(forceTestDc = true).h2Available)
        assertFalse(valid.copy(noSecure = true).toProxySettings().h2Enabled)
    }

    @Test
    fun disabledDomainListsAreKeptButNotUsed() {
        val s = valid.copy(cfUserDomains = "a.example.com", cfWorkerDomains = "w.workers.dev").toProxySettings()
        assertEquals(emptyList<String>(), s.cfproxyUserDomains)
        assertEquals(emptyList<String>(), s.cfproxyWorkerDomains)
        val off = valid.copy(cfproxy = false, cfUserDomainEnabled = true, cfUserDomains = "https://bad/").toProxySettings()
        assertFalse(off.fallbackCfproxy)
        assertEquals(emptyList<String>(), off.cfproxyUserDomains)
    }

    @Test
    fun badDomainIsNamed() {
        expectError(
            valid.copy(cfUserDomainEnabled = true, cfUserDomains = "good.com, https://bad.com/x"),
            ConfigField.CF_USER_DOMAINS, ConfigError.Kind.BAD_DOMAIN, "https://bad.com/x",
        )
        expectError(
            valid.copy(cfWorkerEnabled = true, cfWorkerDomains = "1.2.3.4"),
            ConfigField.CF_WORKER_DOMAINS, ConfigError.Kind.BAD_DOMAIN, "1.2.3.4",
        )
        assertTrue(SettingsDraft.isHostname("xn--d1acufc.xn--p1ai"))
        assertFalse(SettingsDraft.isHostname("example"))
        assertFalse(SettingsDraft.isHostname("example.com:443"))
    }

    @Test
    fun fakeTlsDomain() {
        assertEquals("", valid.toProxySettings().fakeTlsDomain)
        val s = valid.copy(fakeTlsDomain = " Example.com ").toProxySettings()
        assertEquals("example.com", s.fakeTlsDomain)
        val domainHex = "6578616d706c652e636f6d"
        assertEquals(
            "tg://proxy?server=127.0.0.1&port=1443&secret=ee${secret.lowercase()}$domainHex",
            s.proxyLink(),
        )
        expectError(
            valid.copy(fakeTlsDomain = "https://example.com"),
            ConfigField.FAKE_TLS_DOMAIN, ConfigError.Kind.BAD_DOMAIN, "https://example.com",
        )
    }

    @Test
    fun newSecretIsValid() {
        val a = SettingsDraft.newSecret()
        assertEquals(32, a.length)
        assertTrue(valid.copy(secret = a).errors().isEmpty())
        assertTrue(a != SettingsDraft.newSecret())
    }

    @Test
    fun listenErrors() {
        assertEquals(
            ListenProblem.PORT_BUSY,
            diagnoseListenError(BindException("bind failed: EADDRINUSE (Address already in use)")),
        )
        assertEquals(ListenProblem.PORT_BUSY, diagnoseListenError(BindException("Address already in use")))
        assertEquals(
            ListenProblem.PERMISSION,
            diagnoseListenError(BindException("bind failed: EACCES (Permission denied)")),
        )
        assertEquals(
            ListenProblem.BAD_ADDRESS,
            diagnoseListenError(BindException("bind failed: EADDRNOTAVAIL (Cannot assign requested address)")),
        )
        assertEquals(
            ListenProblem.PORT_BUSY,
            diagnoseListenError(java.io.IOException("wrapped", BindException("Address already in use"))),
        )
        assertEquals(ListenProblem.OTHER, diagnoseListenError(java.io.IOException("boom")))
    }
}
