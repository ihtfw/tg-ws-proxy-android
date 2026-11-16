package org.flowseal.tgwsproxy.proxy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.IOException

class UpdateCheckTest {

    private val releaseJson = """
        {
          "url": "https://api.github.com/repos/ihtfw/tg-ws-proxy-android/releases/1",
          "html_url": "https://github.com/ihtfw/tg-ws-proxy-android/releases/tag/v1.4.0",
          "id": 1,
          "author": {"login": "ihtfw", "html_url": "https://github.com/ihtfw", "site_admin": false},
          "tag_name": "v1.4.0",
          "name": "1.4.0 \"MTProto\"—test",
          "draft": false,
          "prerelease": false,
          "assets": [{"name": "app-release.apk", "size": 123456, "browser_download_url": "https://x/y.apk"}],
          "body": "Line 1\nLine 2 \\ path",
          "score": -1.5e3,
          "nothing": null
        }
    """.trimIndent()

    @Test
    fun versions() {
        assertEquals(listOf(1, 3, 0), UpdateCheck.parseVersion("v1.3.0"))
        assertEquals(listOf(1, 3, 0), UpdateCheck.parseVersion("1.3.0-beta2"))
        assertEquals(listOf(2, 0), UpdateCheck.parseVersion("V2.x"))
        assertTrue(UpdateCheck.isNewer("1.10.0", "1.9.9"))
        assertTrue(UpdateCheck.isNewer("v1.3.1", "1.3.0"))
        assertFalse(UpdateCheck.isNewer("1.3", "1.3.0"))
        assertFalse(UpdateCheck.isNewer("1.3.0", "1.3.0"))
        assertFalse(UpdateCheck.isNewer("1.2.9", "1.3"))
    }

    @Test
    fun parsesTheReleaseNotTheAuthor() {
        val r = UpdateCheck.parseRelease(releaseJson)
        assertEquals("1.4.0", r.version)
        assertEquals("https://github.com/ihtfw/tg-ws-proxy-android/releases/tag/v1.4.0", r.htmlUrl)
    }

    @Test
    fun rejectsBadReleases() {
        for (bad in listOf("""{"tag_name": "latest"}""", """{"message": "Not Found"}""", "[]", "{", "")) {
            try {
                UpdateCheck.parseRelease(bad)
                fail("accepted $bad")
            } catch (_: IllegalArgumentException) {
            }
        }
        val elsewhere = UpdateCheck.parseRelease("""{"tag_name": "1.0.0", "html_url": "https://evil.example/"}""")
        assertEquals(UpdateCheck.RELEASES_PAGE, elsewhere.htmlUrl)
    }

    @Test
    fun checkComparesWithInstalledVersion() {
        val newer = UpdateCheck.check("1.3.0") { UpdateCheck.Release("1.4.0", UpdateCheck.RELEASES_PAGE) }
        assertTrue(newer.checked)
        assertTrue(newer.hasUpdate)
        assertFalse(newer.aheadOfRelease)
        assertEquals("1.4.0", newer.latest)
        assertNull(newer.error)

        val same = UpdateCheck.check("1.3.0") { UpdateCheck.Release("1.3.0", UpdateCheck.RELEASES_PAGE) }
        assertFalse(same.hasUpdate)
        assertFalse(same.aheadOfRelease)

        val ahead = UpdateCheck.check("1.5.0") { UpdateCheck.Release("1.4.0", UpdateCheck.RELEASES_PAGE) }
        assertTrue(ahead.aheadOfRelease)

        val offline = UpdateCheck.check("1.3.0") { throw IOException("no network") }
        assertTrue(offline.checked)
        assertFalse(offline.hasUpdate)
        assertEquals("no network", offline.error)
    }

    @Test
    fun miniJson() {
        val v = MiniJson.parse("""{"a": [1, 2.5, true, false, null, "xA\n"], "b": {}}""") as Map<*, *>
        assertEquals(listOf(1L, 2.5, true, false, null, "xA\n"), v["a"])
        assertEquals(emptyMap<String, Any?>(), v["b"])
    }
}
