package org.flowseal.tgwsproxy.proxy

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/**
 * The public Cloudflare proxy domains (upstream proxy/config.py): a built-in list, refreshed
 * hourly from upstream's GitHub, used unless the user set domains of their own. The names are
 * stored shifted, as upstream stores them, and decoded here.
 */
object CfProxyDomains {
    const val DOMAINS_URL = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt"
    private const val MIN_VALID_DOMAINS = 3
    private const val REFRESH_INTERVAL_MIN = 60L

    /** raw.githubusercontent.com is reached at this address first, then through DNS. */
    private val GITHUB_IPS = mapOf("raw.githubusercontent.com" to "185.199.109.133")

    private val ENCODED = listOf(
        "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
        "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
        "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
        "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
    )
    private val SUFFIX = String(charArrayOf(46.toChar(), 99.toChar(), 111.toChar(), 46.toChar(), 117.toChar(), 107.toChar()))

    val DEFAULT_DOMAINS: List<String> = ENCODED.map(::decode)

    /** The last good list: the built-in one until a refresh succeeds. */
    @Volatile var latest: List<String> = DEFAULT_DOMAINS
        private set

    /** The domains the CF proxy fallback and the connectivity check use for [settings]. */
    fun current(settings: ProxySettings): List<String> =
        settings.cfproxyUserDomains.ifEmpty { latest }

    /** Upstream's _dd: letters shifted back by the count of letters, ".com" replaced. */
    fun decode(s: String): String {
        if (!s.endsWith(".com")) return s
        val p = s.substring(0, s.length - 4)
        val n = p.count { it.isLetter() }
        val sb = StringBuilder()
        for (c in p) {
            if (c in 'a'..'z' || c in 'A'..'Z') {
                val base = if (c > '`') 'a'.code else 'A'.code
                sb.append((Math.floorMod(c.code - base - n, 26) + base).toChar())
            } else sb.append(c)
        }
        return sb.append(SUFFIX).toString()
    }

    fun isValidDomain(domain: String): Boolean {
        if (domain.isEmpty() || domain.length > 253) return false
        if (domain.startsWith('.') || domain.endsWith('.')) return false
        val labels = domain.split('.')
        if (labels.size < 2) return false
        for (label in labels) {
            if (label.isEmpty() || label.length > 63) return false
            if (label.first() == '-' || label.last() == '-') return false
            if (!label.all { it.isLetterOrDigit() && it.code < 128 || it == '-' }) return false
        }
        val tld = labels.last()
        return tld.length >= 2 && tld.any { it.isLetter() }
    }

    fun normalize(domains: List<String>): List<String> {
        val seen = HashSet<String>()
        val out = ArrayList<String>()
        for (d in domains) {
            val item = d.trim().lowercase()
            if (!isValidDomain(item) || !seen.add(item)) continue
            out.add(item)
        }
        return out
    }

    fun parseList(text: String): List<String> =
        text.lines().map { it.trim() }.filter { it.isNotEmpty() && !it.startsWith("#") }.map(::decode)

    /** Starts the balancer on the built-in list and refreshes it now and every hour. */
    fun startRefresh(ctx: ProxyContext): ScheduledFuture<*> {
        ctx.balancer.updateDomainsList(latest)
        return ctx.scheduler.scheduleWithFixedDelay({ refresh(ctx) }, 0, REFRESH_INTERVAL_MIN, TimeUnit.MINUTES)
    }

    fun refresh(ctx: ProxyContext) {
        if (ctx.settings.cfproxyUserDomains.isNotEmpty() || ctx.stopped) return
        val fetched = try {
            parseList(fetch(DOMAINS_URL + "?" + randomLetters(7)))
        } catch (e: Exception) {
            ProxyLog.w("Failed to fetch CF proxy domain list: ${errStr(e)}")
            emptyList()
        }
        val pool = normalize(fetched)
        if (pool.size >= MIN_VALID_DOMAINS) {
            latest = pool
            ctx.balancer.updateDomainsList(pool)
            ProxyLog.i("CF proxy domain pool updated from GitHub (${pool.size} domains)")
        } else if (fetched.isNotEmpty()) {
            ProxyLog.w(
                "Ignoring fetched CF proxy domains due to low-quality payload " +
                    "(total=${fetched.size}, valid=${pool.size}, required>=$MIN_VALID_DOMAINS); keeping current domain pool"
            )
        } else {
            ProxyLog.w("CF proxy domain refresh failed or empty response; keeping current domain pool")
        }
    }

    private fun randomLetters(n: Int): String {
        val letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        return (1..n).map { letters[Bytes.random.nextInt(letters.length)] }.joinToString("")
    }

    /** GET over HTTPS, trying the pinned GitHub address before DNS (upstream build_github_opener). */
    fun fetch(url: String, timeoutMs: Int = 10_000): String {
        val u = URL(url)
        val pinned = GITHUB_IPS[u.host]
        if (pinned != null) {
            try {
                return fetchVia(pinned, u, timeoutMs)
            } catch (e: Exception) {
                ProxyLog.d { "pinned fetch of ${u.host} failed: ${errStr(e)}" }
            }
        }
        val conn = u.openConnection() as HttpURLConnection
        try {
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.setRequestProperty("User-Agent", "tg-ws-proxy")
            if (conn.responseCode != 200) throw java.io.IOException("HTTP ${conn.responseCode}")
            return conn.inputStream.use { String(it.readBytes(), Charsets.UTF_8) }
        } finally {
            conn.disconnect()
        }
    }

    private fun fetchVia(ip: String, u: URL, timeoutMs: Int): String {
        val raw = Socket()
        raw.connect(InetSocketAddress(ip, 443), timeoutMs)
        raw.soTimeout = timeoutMs
        val ssl = (SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(raw, u.host, 443, true) as SSLSocket
        ssl.use {
            ssl.startHandshake()
            if (!HostCheck.matches(ssl.session, u.host)) {
                throw SSLException("certificate does not match ${u.host}")
            }
            val path = u.file.ifEmpty { "/" }
            ssl.outputStream.write(
                ("GET $path HTTP/1.0\r\nHost: ${u.host}\r\nUser-Agent: tg-ws-proxy\r\n" +
                    "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").toByteArray(Charsets.US_ASCII)
            )
            ssl.outputStream.flush()
            val all = ByteArrayOutputStream()
            BufferedInputStream(ssl.inputStream).copyTo(all)
            val bytes = all.toByteArray()
            val text = String(bytes, Charsets.UTF_8)
            val headerEnd = text.indexOf("\r\n\r\n")
            if (headerEnd < 0) throw java.io.IOException("no HTTP header end")
            val status = text.substring(0, text.indexOf("\r\n")).split(' ').getOrNull(1)?.toIntOrNull()
            if (status != 200) throw java.io.IOException("HTTP $status")
            return text.substring(headerEnd + 4)
        }
    }
}
