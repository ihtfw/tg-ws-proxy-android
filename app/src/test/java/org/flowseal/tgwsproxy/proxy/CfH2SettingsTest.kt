package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Which settings select the H2 media route (upstream tests/test_h2_settings.py; the CLI, GUI and
 * saved-config parts of it belong to the settings screen, not to the proxy core).
 */
class CfH2SettingsTest {

    @Test
    fun h2IsOnByDefaultAndOffWithAnyBlockingSetting() {
        val base = ProxySettings(secretHex = "ab".repeat(16))
        val cases = listOf(
            base to true,
            base.copy(cfproxyH2Media = false) to false,
            base.copy(fallbackCfproxy = false) to false,
            base.copy(disableSecure = true) to false,
            base.copy(forceTestDc = true) to false,
        )
        for ((settings, enabled) in cases) {
            assertEquals(settings.toString(), enabled, settings.h2Enabled)
        }
    }

    @Test
    fun turningABlockingSettingBackOffRestoresH2WithoutTouchingTheMediaOption() {
        val blocked = ProxySettings(secretHex = "ab".repeat(16), fallbackCfproxy = false)
        assertTrue(blocked.cfproxyH2Media)
        assertTrue(blocked.copy(fallbackCfproxy = true).h2Enabled)
    }

    @Test
    fun poolDefaultsMatchUpstreamLimits() {
        val t = CfH2Tuning()
        assertEquals(4 * 1024 * 1024, t.maxPacket)
        assertEquals(8, t.maxChannelRequests)
        assertEquals(64, t.maxLaneRequests)
        assertEquals(8.0, t.setupTimeout, 0.0)
        assertEquals(30.0, t.domainCooldown, 0.0)
        assertEquals(65.0, t.requestTimeout, 0.0)
        assertEquals(3, t.replayMaxAttempts)
    }
}
