package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL

/**
 * Asks GitHub for the latest release of this app and compares it with the installed version
 * (upstream utils/update_check.py, without the self-install). Blocking; call it off the main thread.
 */
object UpdateCheck {
    const val REPO = "ihtfw/tg-ws-proxy-android"
    const val LATEST_API = "https://api.github.com/repos/$REPO/releases/latest"
    const val RELEASES_PAGE = "https://github.com/$REPO/releases/latest"
    private const val MAX_RESPONSE = 1 shl 20

    data class Release(val version: String, val htmlUrl: String)

    data class Status(
        val checked: Boolean = false,
        val latest: String? = null,
        val hasUpdate: Boolean = false,
        /** The installed version is newer than the latest release (a development build). */
        val aheadOfRelease: Boolean = false,
        val htmlUrl: String = RELEASES_PAGE,
        val error: String? = null,
    )

    /** "v1.3.0" and "1.3.0-beta" both give [1, 3, 0]; a part without digits counts as 0. */
    fun parseVersion(s: String): List<Int> =
        s.trim().trimStart('v', 'V').split('.').map { part ->
            Regex("^\\d+").find(part)?.value?.toIntOrNull() ?: 0
        }

    /** a > b, comparing the numeric parts with missing parts as 0 ("1.3" == "1.3.0"). */
    fun isNewer(a: String, b: String): Boolean {
        val x = parseVersion(a)
        val y = parseVersion(b)
        for (i in 0 until maxOf(x.size, y.size)) {
            val p = x.getOrElse(i) { 0 }
            val q = y.getOrElse(i) { 0 }
            if (p != q) return p > q
        }
        return false
    }

    /** The tag and page of a GitHub "latest release" answer. @throws IllegalArgumentException */
    fun parseRelease(json: String): Release {
        val data = MiniJson.parse(json) as? Map<*, *> ?: throw IllegalArgumentException("Invalid release from GitHub")
        val tag = (data["tag_name"] as? String)?.trim()?.trimStart('v', 'V')
            ?: throw IllegalArgumentException("Invalid release from GitHub")
        require(tag.isNotEmpty() && tag[0].isDigit()) { "Invalid release version from GitHub: $tag" }
        val page = (data["html_url"] as? String)?.takeIf { it.startsWith("https://github.com/") } ?: RELEASES_PAGE
        return Release(tag, page)
    }

    fun fetchLatest(timeoutMs: Int = 12_000): Release {
        val conn = URL(LATEST_API).openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("Accept", "application/vnd.github+json")
            conn.setRequestProperty("User-Agent", "tg-ws-proxy-android-update-check")
            val code = conn.responseCode
            if (code != HttpURLConnection.HTTP_OK) throw IOException("GitHub answered HTTP $code")
            val out = ByteArrayOutputStream()
            conn.inputStream.use { input ->
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = input.read(buf)
                    if (n < 0) break
                    out.write(buf, 0, n)
                    if (out.size() > MAX_RESPONSE) throw IOException("GitHub answer too large")
                }
            }
            return parseRelease(out.toString("UTF-8"))
        } finally {
            conn.disconnect()
        }
    }

    /** The whole result at once; failures end up in [Status.error]. */
    fun check(currentVersion: String, fetch: () -> Release = { fetchLatest() }): Status = try {
        val release = fetch()
        Status(
            checked = true,
            latest = release.version,
            hasUpdate = isNewer(release.version, currentVersion),
            aheadOfRelease = isNewer(currentVersion, release.version),
            htmlUrl = release.htmlUrl,
        )
    } catch (e: Exception) {
        Status(checked = true, error = e.message ?: e.javaClass.simpleName)
    }
}

/** Just enough JSON for the GitHub answer: objects, arrays, strings, numbers, true/false/null. */
internal class MiniJson private constructor(private val s: String) {
    private var i = 0

    companion object {
        fun parse(text: String): Any? {
            val p = MiniJson(text)
            val v = p.value()
            p.ws()
            require(p.i == text.length) { "Trailing data in JSON at ${p.i}" }
            return v
        }
    }

    private fun ws() {
        while (i < s.length && s[i].isWhitespace()) i++
    }

    private fun value(): Any? {
        ws()
        require(i < s.length) { "Unexpected end of JSON" }
        return when (val c = s[i]) {
            '{' -> obj()
            '[' -> arr()
            '"' -> str()
            't' -> literal("true", true)
            'f' -> literal("false", false)
            'n' -> literal("null", null)
            else -> if (c == '-' || c.isDigit()) num() else throw IllegalArgumentException("Bad JSON at $i")
        }
    }

    private fun literal(word: String, v: Any?): Any? {
        require(s.startsWith(word, i)) { "Bad JSON at $i" }
        i += word.length
        return v
    }

    private fun obj(): Map<String, Any?> {
        val m = LinkedHashMap<String, Any?>()
        i++
        ws()
        if (s.getOrNull(i) == '}') { i++; return m }
        while (true) {
            ws()
            require(s.getOrNull(i) == '"') { "Expected key at $i" }
            val k = str()
            ws()
            require(s.getOrNull(i) == ':') { "Expected ':' at $i" }
            i++
            m[k] = value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> i++
                '}' -> { i++; return m }
                else -> throw IllegalArgumentException("Expected ',' or '}' at $i")
            }
        }
    }

    private fun arr(): List<Any?> {
        val l = ArrayList<Any?>()
        i++
        ws()
        if (s.getOrNull(i) == ']') { i++; return l }
        while (true) {
            l += value()
            ws()
            when (s.getOrNull(i)) {
                ',' -> i++
                ']' -> { i++; return l }
                else -> throw IllegalArgumentException("Expected ',' or ']' at $i")
            }
        }
    }

    private fun str(): String {
        val sb = StringBuilder()
        i++
        while (true) {
            require(i < s.length) { "Unterminated string" }
            val c = s[i++]
            when (c) {
                '"' -> return sb.toString()
                '\\' -> {
                    require(i < s.length) { "Unterminated string" }
                    when (val e = s[i++]) {
                        '"', '\\', '/' -> sb.append(e)
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            require(i + 4 <= s.length) { "Bad \\u escape" }
                            sb.append(s.substring(i, i + 4).toInt(16).toChar())
                            i += 4
                        }
                        else -> throw IllegalArgumentException("Bad escape \\$e")
                    }
                }
                else -> sb.append(c)
            }
        }
    }

    private fun num(): Number {
        val start = i
        if (s[i] == '-') i++
        while (i < s.length && (s[i].isDigit() || s[i] in ".eE+-")) i++
        val t = s.substring(start, i)
        return t.toLongOrNull() ?: t.toDouble()
    }
}
