package org.flowseal.tgwsproxy.proxy

/**
 * Logging for the proxy core. Kept free of android.* so the core runs in JVM unit tests;
 * the service installs a sink that feeds logcat and the in-app log.
 */
object ProxyLog {
    enum class Level { DEBUG, INFO, WARN, ERROR }

    /** Debug lines are dropped unless verbose logging is on. */
    @Volatile var verbose: Boolean = false

    /** Hide non-Telegram domain names in log lines (upstream's DomainCensorFilter). */
    @Volatile var censorDomains: Boolean = true

    @Volatile var sink: (Level, String) -> Unit = { level, msg -> println("${level.name.padEnd(5)} $msg") }

    fun d(msg: String) { if (verbose) emit(Level.DEBUG, msg) }
    fun d(msg: () -> String) { if (verbose) emit(Level.DEBUG, msg()) }
    fun i(msg: String) = emit(Level.INFO, msg)
    fun w(msg: String) = emit(Level.WARN, msg)
    fun e(msg: String) = emit(Level.ERROR, msg)

    private fun emit(level: Level, msg: String) {
        try {
            sink(level, if (censorDomains) censor(msg) else msg)
        } catch (_: Throwable) {
        }
    }

    /** Dotted names that are class names in stack traces and exceptions, not domains. */
    private val CODE_PREFIXES = listOf(
        "java.", "javax.", "android.", "androidx.", "kotlin.", "kotlinx.", "dalvik.", "libcore.",
        "sun.", "jdk.", "org.flowseal.", "okhttp3.", "okio.", "org.conscrypt.", "com.android.",
    )

    private val domainPattern = Regex(
        "(?<![\\w-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}(?![\\w-])"
    )

    /**
     * Masks the second half of every label except the TLD, leaving telegram.org names
     * and *.log file names as they are: "example.com" becomes "exa****.com".
     */
    fun censor(text: String): String = domainPattern.replace(text) { m ->
        val domain = m.value
        val normalized = domain.lowercase().trimEnd('.')
        if (CODE_PREFIXES.any { normalized.startsWith(it) }) return@replace domain
        if (normalized == "telegram.org" || normalized.endsWith(".telegram.org") || normalized.endsWith(".log")) {
            return@replace domain
        }
        val parts = domain.split('.')
        if (parts.size < 2) return@replace domain
        parts.mapIndexed { i, part ->
            if (i == parts.size - 1) part
            else part.substring(0, part.length / 2) + "*".repeat(part.length - part.length / 2)
        }.joinToString(".")
    }
}
