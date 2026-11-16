package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.concurrent.ExecutionException
import java.util.concurrent.Future
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Fake TLS, the server side of an "ee" secret (upstream proxy/fake_tls.py): the client's
 * ClientHello carries an HMAC of the secret, the proxy answers with a ServerHello flight that
 * looks like a TLS 1.3 server's, and the MTProto stream then travels inside ApplicationData
 * records. Clients that fail the check, and replayed hellos, are forwarded to the real masking
 * site, so a prober sees that site.
 */
object FakeTls {
    const val TLS_RECORD_HANDSHAKE = 0x16
    const val TLS_RECORD_CCS = 0x14
    const val TLS_RECORD_APPDATA = 0x17

    const val CLIENT_RANDOM_OFFSET = 11
    const val CLIENT_RANDOM_LEN = 32
    const val SESSION_ID_OFFSET = 44
    const val SESSION_ID_LEN = 32

    /** Seconds a ClientHello timestamp may differ from our clock. */
    const val TIMESTAMP_TOLERANCE = 120

    const val TLS_APPDATA_MAX = 16384

    const val EXT_SUPPORTED_VERSIONS = 0x002b
    const val EXT_KEY_SHARE = 0x0033

    const val GROUP_X25519 = 0x001d
    const val GROUP_X25519MLKEM768 = 0x11ec

    const val X25519_KEY_LEN = 32
    const val X25519MLKEM768_CLIENT_SHARE_LEN = 1216
    const val MLKEM768_CIPHERTEXT_LEN = 1088

    /** TLS 1.3 suites in the order a typical server picks them from the client's list. */
    val CIPHER_PREFERENCE = listOf(0x1301, 0x1303, 0x1302)

    /**
     * Bounds for the single ApplicationData record after CCS: the low one matches the smallest
     * record telemt emits, the high one is the TLS limit.
     */
    const val APPDATA_MIN = 64

    /**
     * Without a site profile stay near the 64-byte record telemt passed DPI with, far from the
     * 1900-2100 bytes of the classic MTProxy answer.
     */
    val FALLBACK_APPDATA_RANGE = 64..160

    /** The ServerHello goes out after a random pause in this range, in microseconds. */
    const val SERVER_HELLO_DELAY_MIN_US = 8_000L
    const val SERVER_HELLO_DELAY_MAX_US = 24_000L

    const val PROFILE_PROBE_TIMEOUT_MS = 5000

    const val MASKING_PORT = 443
    const val MASKING_CONNECT_TIMEOUT_MS = 10_000

    /**
     * A ClientHello passes the timestamp check for TIMESTAMP_TOLERANCE on either side of its
     * creation, plus up to a second because the check truncates the clock; remembering its random
     * this long refuses any replay.
     */
    const val REPLAY_WINDOW_MS = (2L * TIMESTAMP_TOLERANCE + 1) * 1000

    /**
     * Only hellos that passed the HMAC check are stored, so without the secret nobody can flood
     * the cache to evict an entry early; reaching the limit takes this many genuine handshakes
     * within one window.
     */
    const val REPLAY_CACHE_SIZE = 65536

    private val CCS_FRAME = byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01)
    private const val SH_RANDOM_OFF = 11

    /**
     * One cache per process on purpose: it survives proxy restarts, so a hello accepted just
     * before a restart cannot be replayed right after it.
     */
    val replayCache = ReplayCache()

    /**
     * Size of the masking site's first encrypted record after its ServerHello, clamped to
     * [APPDATA_MIN]..[TLS_APPDATA_MAX]; set once at startup from [probeAppdataLen], null for
     * random sizes in [FALLBACK_APPDATA_RANGE].
     */
    @Volatile var profiledAppdataLen: Int? = null
        set(value) {
            field = value?.coerceIn(APPDATA_MIN, TLS_APPDATA_MAX)
        }

    // ---- ClientHello ----

    /**
     * Checks a whole ClientHello record against [secret]: the client random is
     * HMAC-SHA256(secret, record with the random zeroed), its last 4 bytes XORed with a
     * little-endian Unix timestamp that must be within [TIMESTAMP_TOLERANCE] of [nowMs].
     */
    fun verifyClientHello(
        data: ByteArray,
        secret: ByteArray,
        nowMs: Long = System.currentTimeMillis(),
    ): ClientHelloResult? {
        val n = data.size
        // 5 (record header) + 6 (handshake type, length, version) + 32 (random)
        if (n < 43) return null
        if ((data[0].toInt() and 0xFF) != TLS_RECORD_HANDSHAKE) return null
        if (data[5].toInt() != 0x01) return null

        val clientRandom = data.copyOfRange(CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN)
        val zeroed = data.copyOf()
        java.util.Arrays.fill(zeroed, CLIENT_RANDOM_OFFSET, CLIENT_RANDOM_OFFSET + CLIENT_RANDOM_LEN, 0)
        val expected = Bytes.hmacSha256(secret, zeroed)

        if (!MessageDigest.isEqual(expected.copyOf(28), clientRandom.copyOf(28))) return null

        var timestamp = 0L
        for (i in 0 until 4) {
            val b = (clientRandom[28 + i].toInt() xor expected[28 + i].toInt()) and 0xFF
            timestamp = timestamp or (b.toLong() shl (8 * i))
        }
        val now = nowMs / 1000
        if (kotlin.math.abs(now - timestamp) > TIMESTAMP_TOLERANCE) return null

        val sessionId = if (n >= SESSION_ID_OFFSET + SESSION_ID_LEN && data[43].toInt() == 0x20) {
            data.copyOfRange(SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LEN)
        } else {
            ByteArray(SESSION_ID_LEN)
        }
        return ClientHelloResult(clientRandom, sessionId, timestamp)
    }

    /**
     * The cipher suites and key_share groups a ClientHello offers. Empty on malformed input, so
     * the answer falls back to plain X25519 / TLS_AES_128_GCM_SHA256.
     */
    fun parseClientHello(data: ByteArray): ClientHelloInfo {
        try {
            var pos = 5 + 4 + 2 + CLIENT_RANDOM_LEN
            pos += 1 + (data[pos].toInt() and 0xFF)

            val suitesLen = Bytes.u16be(data, pos)
            pos += 2
            val suitesEnd = pos + suitesLen
            if (suitesEnd > data.size) return ClientHelloInfo.EMPTY
            val suites = HashSet<Int>()
            var off = pos
            while (off < suitesEnd - 1) {
                suites.add(Bytes.u16be(data, off))
                off += 2
            }
            pos = suitesEnd

            pos += 1 + (data[pos].toInt() and 0xFF)

            val extTotal = Bytes.u16be(data, pos)
            pos += 2
            val extEnd = minOf(pos + extTotal, data.size)
            val keyShares = LinkedHashMap<Int, Int>()
            while (pos + 4 <= extEnd) {
                val extType = Bytes.u16be(data, pos)
                val extLen = Bytes.u16be(data, pos + 2)
                pos += 4
                if (extType == EXT_KEY_SHARE && pos + 2 <= extEnd) {
                    val sharesEnd = minOf(pos + 2 + Bytes.u16be(data, pos), extEnd)
                    var shareOff = pos + 2
                    while (shareOff + 4 <= sharesEnd) {
                        val group = Bytes.u16be(data, shareOff)
                        val keyLen = Bytes.u16be(data, shareOff + 2)
                        shareOff += 4 + keyLen
                        if (shareOff <= sharesEnd && group !in keyShares) keyShares[group] = keyLen
                    }
                }
                pos += extLen
            }
            return ClientHelloInfo(suites, keyShares)
        } catch (_: IndexOutOfBoundsException) {
            return ClientHelloInfo.EMPTY
        }
    }

    internal fun selectCipherSuite(info: ClientHelloInfo): Int =
        CIPHER_PREFERENCE.firstOrNull { it in info.cipherSuites } ?: CIPHER_PREFERENCE[0]

    private fun x25519PublicKey(): ByteArray = X25519.publicKey(X25519.generatePrivateKey())

    /**
     * Mirrors the hybrid post-quantum group when the client offers it, as current browsers and
     * servers do; the client never derives keys from it, so the ML-KEM part is random bytes.
     */
    internal fun serverKeyShare(info: ClientHelloInfo): Pair<Int, ByteArray> =
        if (info.keyShares[GROUP_X25519MLKEM768] == X25519MLKEM768_CLIENT_SHARE_LEN) {
            GROUP_X25519MLKEM768 to (Bytes.random(MLKEM768_CIPHERTEXT_LEN) + x25519PublicKey())
        } else {
            GROUP_X25519 to x25519PublicKey()
        }

    private fun appdataLen(): Int =
        profiledAppdataLen
            ?: ThreadLocalRandom.current().nextInt(FALLBACK_APPDATA_RANGE.first, FALLBACK_APPDATA_RANGE.last + 1)

    // ---- ServerHello ----

    /**
     * ServerHello + CCS + one ApplicationData record, the server random being
     * HMAC-SHA256(secret, clientRandom + the flight with the random zeroed). Telegram clients
     * parse exactly these three records and check the HMAC over all of them, so the shape must
     * stay fixed while the sizes may vary.
     */
    fun buildServerHello(
        secret: ByteArray,
        clientRandom: ByteArray,
        sessionId: ByteArray,
        info: ClientHelloInfo = ClientHelloInfo.EMPTY,
    ): ByteArray {
        val (group, keyExchange) = serverKeyShare(info)
        val extensions = Buf().apply {
            u16(EXT_SUPPORTED_VERSIONS); u16(2); u16(0x0304)
            u16(EXT_KEY_SHARE); u16(4 + keyExchange.size); u16(group); u16(keyExchange.size)
            bytes(keyExchange)
        }.toByteArray()

        val body = Buf().apply {
            u16(0x0303)
            bytes(ByteArray(32))
            u8(sessionId.size); bytes(sessionId)
            u16(selectCipherSuite(info))
            u8(0)
            u16(extensions.size); bytes(extensions)
        }.toByteArray()

        val appdataLen = appdataLen()
        val response = Buf().apply {
            // ServerHello record
            u8(TLS_RECORD_HANDSHAKE); u16(0x0303); u16(4 + body.size)
            u8(0x02); u24(body.size); bytes(body)
            bytes(CCS_FRAME)
            u8(TLS_RECORD_APPDATA); u16(0x0303); u16(appdataLen)
            bytes(Bytes.random(appdataLen))
        }.toByteArray()

        val serverRandom = Bytes.hmacSha256(secret, clientRandom + response)
        System.arraycopy(serverRandom, 0, response, SH_RANDOM_OFF, 32)
        return response
    }

    // ---- Masking site profile ----

    /**
     * Length of the first ApplicationData record in a server's first flight: null while more
     * data is needed, 0 if the flight cannot contain one (an alert, garbage).
     */
    fun firstAppdataRecordLen(data: ByteArray, length: Int = data.size): Int? {
        var pos = 0
        while (pos + 5 <= length) {
            val type = data[pos].toInt() and 0xFF
            val recLen = Bytes.u16be(data, pos + 3)
            if (type == TLS_RECORD_APPDATA) return recLen
            if (type != TLS_RECORD_HANDSHAKE && type != TLS_RECORD_CCS) return 0
            pos += 5 + recLen
        }
        return null
    }

    /**
     * Measures the first encrypted record [domain] sends after its ServerHello. Sends a TLS 1.3
     * ClientHello offering only X25519 and reads the raw first flight; the handshake is never
     * completed. One deadline of [timeoutMs] covers connecting, sending and reading.
     * Blocking (and the DNS lookup is not bounded by the timeout): call it off the main thread.
     */
    fun probeAppdataLen(domain: String, port: Int = 443, timeoutMs: Int = PROFILE_PROBE_TIMEOUT_MS): Int? {
        val sock = Socket()
        try {
            val hello = buildProbeClientHello(domain)
            val deadline = System.nanoTime() + timeoutMs * 1_000_000L
            sock.connect(InetSocketAddress(domain, port), maxOf(1, timeoutMs))
            sock.tcpNoDelay = true
            val out = sock.getOutputStream()
            out.write(hello)
            out.flush()

            val input = sock.getInputStream()
            val flight = ByteArrayOutputStream()
            val buf = ByteArray(16384)
            while (true) {
                val remainingMs = (deadline - System.nanoTime()) / 1_000_000
                if (remainingMs <= 0) throw SocketTimeoutException("no encrypted record within $timeoutMs ms")
                sock.soTimeout = remainingMs.toInt()
                val n = input.read(buf)
                if (n < 0) return null
                flight.write(buf, 0, n)
                val length = firstAppdataRecordLen(flight.toByteArray()) ?: continue
                return if (length == 0) null else length
            }
        } catch (e: Exception) {
            ProxyLog.w("Fake TLS profile: cannot probe $domain:$port: ${describe(e)}")
            return null
        } finally {
            sock.closeQuietly()
        }
    }

    /**
     * Upstream's startup step: forget the old profile and, for a non-empty [domain], probe it and
     * keep the result in [profiledAppdataLen]. Blocking for up to the probe timeout.
     */
    fun profileMaskingSite(domain: String): Int? {
        profiledAppdataLen = null
        if (domain.isEmpty()) return null
        val length = probeAppdataLen(domain)
        profiledAppdataLen = length
        if (length == null) {
            ProxyLog.w("Fake TLS profile unavailable, ServerHello uses random record sizes")
        } else {
            ProxyLog.i("Fake TLS profile: first encrypted record $length bytes")
        }
        return length
    }

    /**
     * A TLS 1.3-only ClientHello like the one upstream's OpenSSL sends for the probe: TLS 1.3
     * suites, X25519 alone (with a real key share), ALPN h2/http/1.1 and SNI unless [domain] is
     * an IP address.
     */
    internal fun buildProbeClientHello(domain: String): ByteArray {
        val ext = Buf()
        if (!ProxySettings.isIpv4(domain) && ':' !in domain) {
            val name = try {
                java.net.IDN.toASCII(domain)
            } catch (_: IllegalArgumentException) {
                domain
            }.toByteArray(Charsets.US_ASCII)
            ext.u16(0x0000); ext.u16(name.size + 5); ext.u16(name.size + 3)
            ext.u8(0); ext.u16(name.size); ext.bytes(name)
        }
        // supported_groups
        ext.u16(0x000a); ext.u16(4); ext.u16(2); ext.u16(GROUP_X25519)
        // session_ticket
        ext.u16(0x0023); ext.u16(0)
        // application_layer_protocol_negotiation
        val alpn = Buf().apply {
            for (p in listOf("h2", "http/1.1")) {
                val b = p.toByteArray(Charsets.US_ASCII)
                u8(b.size); bytes(b)
            }
        }.toByteArray()
        ext.u16(0x0010); ext.u16(alpn.size + 2); ext.u16(alpn.size); ext.bytes(alpn)
        // extended_master_secret
        ext.u16(0x0017); ext.u16(0)
        // signature_algorithms
        val sigAlgs = intArrayOf(
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808, 0x0809, 0x080a, 0x080b,
            0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
        )
        ext.u16(0x000d); ext.u16(2 + 2 * sigAlgs.size); ext.u16(2 * sigAlgs.size)
        for (s in sigAlgs) ext.u16(s)
        // supported_versions: TLS 1.3 only
        ext.u16(EXT_SUPPORTED_VERSIONS); ext.u16(3); ext.u8(2); ext.u16(0x0304)
        // psk_key_exchange_modes: psk_dhe_ke
        ext.u16(0x002d); ext.u16(2); ext.u8(1); ext.u8(1)
        // key_share
        val pub = x25519PublicKey()
        ext.u16(EXT_KEY_SHARE); ext.u16(2 + 4 + pub.size); ext.u16(4 + pub.size)
        ext.u16(GROUP_X25519); ext.u16(pub.size); ext.bytes(pub)
        val extensions = ext.toByteArray()

        val suites = intArrayOf(0x1302, 0x1303, 0x1301, 0x00ff)
        val body = Buf().apply {
            u16(0x0303)
            bytes(Bytes.random(32))
            u8(SESSION_ID_LEN); bytes(Bytes.random(SESSION_ID_LEN))
            u16(2 * suites.size)
            for (s in suites) u16(s)
            u8(1); u8(0)
            u16(extensions.size); bytes(extensions)
        }.toByteArray()

        return Buf().apply {
            u8(TLS_RECORD_HANDSHAKE); u16(0x0301); u16(4 + body.size)
            u8(0x01); u24(body.size); bytes(body)
        }.toByteArray()
    }

    // ---- Records ----

    /** [data] as ApplicationData records of at most [TLS_APPDATA_MAX] bytes; nothing for no data. */
    fun wrapTlsRecord(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): ByteArray {
        val records = (length + TLS_APPDATA_MAX - 1) / TLS_APPDATA_MAX
        val out = ByteArray(length + 5 * records)
        var src = offset
        var dst = 0
        var left = length
        while (left > 0) {
            val chunk = minOf(left, TLS_APPDATA_MAX)
            out[dst] = TLS_RECORD_APPDATA.toByte()
            out[dst + 1] = 0x03
            out[dst + 2] = 0x03
            out[dst + 3] = (chunk ushr 8).toByte()
            out[dst + 4] = chunk.toByte()
            System.arraycopy(data, src, out, dst + 5, chunk)
            src += chunk
            dst += 5 + chunk
            left -= chunk
        }
        return out
    }

    // ---- The server's entry point ----

    /**
     * Called after the server read the first byte [firstByte] == 0x16 from the client.
     * Reads the rest of the ClientHello, verifies it against [secret]; on failure or replay forwards
     * the client to [maskingDomain] (blocking until that ends) and returns null. On success writes
     * the ServerHello (after the delay) and returns streams that unwrap/wrap TLS appdata records;
     * the caller then reads the 64-byte obfuscated init from the returned input.
     *
     * Returns null too when the client disconnects inside the ClientHello. Read timeouts are the
     * caller's socket timeout and propagate as SocketTimeoutException, as upstream's
     * asyncio.TimeoutError does. [maskingPort] is for tests.
     */
    fun accept(
        firstByte: Int,
        input: InputStream,
        output: OutputStream,
        secret: ByteArray,
        maskingDomain: String,
        label: String,
        ctx: ProxyContext,
        maskingPort: Int = MASKING_PORT,
    ): Pair<InputStream, OutputStream>? {
        val headerRest = try {
            input.readExactly(4)
        } catch (_: EOFException) {
            ProxyLog.d { "[$label] incomplete TLS record header" }
            return null
        }
        val recordLen = Bytes.u16be(headerRest, 2)
        val clientHello = ByteArray(5 + recordLen)
        clientHello[0] = firstByte.toByte()
        System.arraycopy(headerRest, 0, clientHello, 1, 4)
        try {
            System.arraycopy(input.readExactly(recordLen), 0, clientHello, 5, recordLen)
        } catch (_: EOFException) {
            ProxyLog.d { "[$label] incomplete TLS record body" }
            return null
        }

        val result = verifyClientHello(clientHello, secret)
        // A recorded hello stays valid for minutes; answering it again would tell an active
        // prober that this is a proxy, not the masking site
        val replayed = result != null && !replayCache.firstSeen(result.clientRandom)

        if (result == null || replayed) {
            ProxyLog.d {
                "[$label] Fake TLS ${if (replayed) "hello replayed" else "verify failed"} " +
                    "(size=${clientHello.size} rec=$recordLen) -> masking"
            }
            proxyToMaskingDomain(input, output, clientHello, maskingDomain, label, ctx, maskingPort)
            return null
        }

        ProxyLog.d { "[$label] Fake TLS handshake ok (ts=${result.timestamp})" }

        val serverHello = buildServerHello(
            secret, result.clientRandom, result.sessionId, parseClientHello(clientHello),
        )
        serverHelloDelay()
        output.write(serverHello)
        output.flush()

        return FakeTlsInputStream(input) to FakeTlsOutputStream(output)
    }

    private fun serverHelloDelay() {
        val us = ThreadLocalRandom.current().nextLong(SERVER_HELLO_DELAY_MIN_US, SERVER_HELLO_DELAY_MAX_US + 1)
        try {
            Thread.sleep(us / 1000, ((us % 1000) * 1000).toInt())
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw InterruptedIOException("interrupted before ServerHello")
        }
    }

    // ---- Masking ----

    /**
     * Forwards the client to the real [domain]: sends [initialData] (the ClientHello already
     * read), then relays both directions until either side ends, counting the connection in
     * stats.connectionsMasked. Blocks until done. Once connected it ends by closing [input] and
     * [output]; when the site is unreachable it only logs and returns.
     */
    fun proxyToMaskingDomain(
        input: InputStream,
        output: OutputStream,
        initialData: ByteArray,
        domain: String,
        label: String,
        ctx: ProxyContext,
        port: Int = MASKING_PORT,
    ) {
        if (domain.isEmpty()) return
        val up = Socket()
        try {
            up.connect(InetSocketAddress(domain, port), MASKING_CONNECT_TIMEOUT_MS)
        } catch (e: Exception) {
            ProxyLog.w("[$label] masking: cannot connect to $domain:$port: ${describe(e)}")
            up.closeQuietly()
            return
        }

        ProxyLog.d { "[$label] masking -> $domain:$port" }
        ctx.stats.connectionsMasked.incrementAndGet()

        val done = AtomicBoolean(false)
        var down: Future<*>? = null
        try {
            up.tcpNoDelay = true
            val upIn = up.getInputStream()
            val upOut = up.getOutputStream()
            if (initialData.isNotEmpty()) {
                upOut.write(initialData)
                upOut.flush()
            }
            val siteToClient = ctx.executor.submit(Runnable {
                relay(upIn, output, done) {
                    output.closeQuietly()
                    input.closeQuietly()
                }
            })
            down = siteToClient
            relay(input, upOut, done) { up.closeQuietly() }
            siteToClient.get()
        } catch (_: IOException) {
        } catch (_: RejectedExecutionException) {
        } catch (_: ExecutionException) {
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        } finally {
            up.closeQuietly()
            down?.cancel(true)
        }
    }

    /** "ConnectException: Connection refused": no package name for the log's domain censoring to mangle. */
    private fun describe(e: Throwable): String =
        e.javaClass.simpleName + (e.message?.let { ": $it" } ?: "")

    /**
     * Copies [src] to [dst] until EOF or an error, then marks [done] and runs [onEnd].
     * A read timeout (the caller's socket timeout on the client side) does not end the relay
     * while the other direction is alive, since upstream relays without a timeout.
     */
    private fun relay(src: InputStream, dst: OutputStream, done: AtomicBoolean, onEnd: () -> Unit) {
        val buf = ByteArray(16384)
        try {
            while (true) {
                val n = try {
                    src.read(buf)
                } catch (e: SocketTimeoutException) {
                    if (done.get()) break else continue
                }
                if (n < 0) break
                dst.write(buf, 0, n)
                dst.flush()
            }
        } catch (_: IOException) {
        } finally {
            done.set(true)
            onEnd()
        }
    }
}

/** What [FakeTls.verifyClientHello] takes from a valid ClientHello. */
class ClientHelloResult(
    val clientRandom: ByteArray,
    /** The client's legacy session id, echoed in the ServerHello; zeros if it sent none. */
    val sessionId: ByteArray,
    /** Unix seconds the client signed into its random. */
    val timestamp: Long,
)

/** The offered cipher suites, and the key_share groups with their key_exchange lengths. */
data class ClientHelloInfo(
    val cipherSuites: Set<Int>,
    val keyShares: Map<Int, Int>,
) {
    companion object {
        val EMPTY = ClientHelloInfo(emptySet(), emptyMap())
    }
}

/**
 * Client randoms of accepted ClientHellos; seeing one again within [windowMs] is a replay probe.
 * Entries expire in insertion order; a full cache drops its oldest entry for a new one.
 */
class ReplayCache(
    val windowMs: Long = FakeTls.REPLAY_WINDOW_MS,
    val maxSize: Int = FakeTls.REPLAY_CACHE_SIZE,
    private val clockMs: () -> Long = { System.nanoTime() / 1_000_000 },
) {
    private val expiry = LinkedHashMap<ByteBuffer, Long>()

    /** True the first time [clientRandom] is seen within the window, and remembers it. */
    @Synchronized
    fun firstSeen(clientRandom: ByteArray): Boolean {
        val now = clockMs()
        // Insertion order is expiry order, so stale entries are at the front
        val values = expiry.values.iterator()
        while (values.hasNext() && values.next() <= now) values.remove()
        val key = ByteBuffer.wrap(clientRandom.copyOf())
        if (expiry.containsKey(key)) return false
        if (expiry.size >= maxSize) {
            val keys = expiry.keys.iterator()
            keys.next()
            keys.remove()
        }
        expiry[key] = now + windowMs
        return true
    }

    @get:Synchronized
    val size: Int get() = expiry.size

    @Synchronized
    fun clear() = expiry.clear()

    /** The remembered randoms, oldest first. */
    @Synchronized
    internal fun keys(): List<ByteArray> = expiry.keys.map { it.array().copyOf() }
}

/**
 * Reads the payload of the ApplicationData records on [source], skipping ChangeCipherSpec
 * records. Any other record type, or EOF, ends the stream (-1); EOF inside a record header
 * throws EOFException.
 */
class FakeTlsInputStream(private val source: InputStream) : InputStream() {
    private var readLeft = 0
    private var eof = false
    private val header = ByteArray(5)
    private val one = ByteArray(1)

    override fun read(): Int {
        val n = read(one, 0, 1)
        return if (n < 0) -1 else one[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (off < 0 || len < 0 || len > b.size - off) throw IndexOutOfBoundsException()
        if (len == 0) return 0
        while (readLeft == 0) {
            if (eof || !nextAppdataRecord()) {
                eof = true
                return -1
            }
        }
        val n = source.read(b, off, minOf(len, readLeft))
        if (n < 0) {
            eof = true
            readLeft = 0
            return -1
        }
        readLeft -= n
        return n
    }

    override fun available(): Int = if (readLeft > 0) minOf(readLeft, source.available()) else 0

    override fun close() = source.close()

    /** Positions on the next ApplicationData record's payload; false at EOF or another record type. */
    private fun nextAppdataRecord(): Boolean {
        while (true) {
            val first = source.read()
            if (first < 0) return false
            header[0] = first.toByte()
            var got = 1
            while (got < 5) {
                val n = source.read(header, got, 5 - got)
                if (n < 0) throw EOFException("EOF inside a TLS record header")
                got += n
            }
            val len = Bytes.u16be(header, 3)
            when (first) {
                FakeTls.TLS_RECORD_CCS -> if (len > 0) source.readExactly(len)
                FakeTls.TLS_RECORD_APPDATA -> {
                    readLeft = len
                    return true
                }
                else -> return false
            }
        }
    }
}

/** Writes everything as ApplicationData records on [sink], one sink write per call. */
class FakeTlsOutputStream(private val sink: OutputStream) : OutputStream() {
    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (off < 0 || len < 0 || len > b.size - off) throw IndexOutOfBoundsException()
        if (len == 0) return
        val wrapped = FakeTls.wrapTlsRecord(b, off, len)
        synchronized(this) { sink.write(wrapped) }
    }

    override fun flush() = sink.flush()

    override fun close() = sink.close()
}

/**
 * X25519 (RFC 7748) on BigInteger, for the ServerHello and probe key shares: JCA has it only
 * from Android API 33. Not constant-time, which is fine here: every private key is random,
 * used for one public key and dropped, and no shared secret is ever computed from it.
 */
object X25519 {
    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val P_MINUS_2: BigInteger = P.subtract(BigInteger.valueOf(2))
    private val A24: BigInteger = BigInteger.valueOf(121665)
    private val BASE_POINT = ByteArray(32).also { it[0] = 9 }

    fun generatePrivateKey(): ByteArray = Bytes.random(32)

    fun publicKey(privateKey: ByteArray): ByteArray = scalarMult(privateKey, BASE_POINT)

    /** X25519(k, u) with RFC 7748's scalar clamping and u-coordinate masking; little-endian. */
    fun scalarMult(scalar: ByteArray, u: ByteArray): ByteArray {
        require(scalar.size == 32 && u.size == 32) { "X25519 inputs are 32 bytes" }
        val k = scalar.copyOf()
        k[0] = (k[0].toInt() and 248).toByte()
        k[31] = ((k[31].toInt() and 127) or 64).toByte()
        val uMasked = u.copyOf()
        uMasked[31] = (uMasked[31].toInt() and 127).toByte()

        val x1 = BigInteger(1, Bytes.reversed(uMasked)).mod(P)
        var x2 = BigInteger.ONE
        var z2 = BigInteger.ZERO
        var x3 = x1
        var z3 = BigInteger.ONE
        var swap = 0
        for (t in 254 downTo 0) {
            val kt = (k[t ushr 3].toInt() ushr (t and 7)) and 1
            swap = swap xor kt
            if (swap == 1) {
                x2 = x3.also { x3 = x2 }
                z2 = z3.also { z3 = z2 }
            }
            swap = kt

            val a = x2.add(z2)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb)
            val c = x3.add(z3)
            val d = x3.subtract(z3)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)
            val sum = da.add(cb)
            val diff = da.subtract(cb)
            x3 = sum.multiply(sum).mod(P)
            z3 = x1.multiply(diff.multiply(diff).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e))).mod(P)
        }
        if (swap == 1) {
            x2 = x3.also { x3 = x2 }
            z2 = z3.also { z3 = z2 }
        }
        val result = x2.multiply(z2.modPow(P_MINUS_2, P)).mod(P)

        val be = result.toByteArray() // big-endian, maybe with a leading sign byte or shorter
        val out = ByteArray(32)
        for (i in 0 until minOf(32, be.size)) out[i] = be[be.size - 1 - i]
        return out
    }
}

/** A byte builder for TLS structures. */
private class Buf : ByteArrayOutputStream() {
    fun u8(v: Int) = write(v and 0xFF)
    fun u16(v: Int) {
        write((v ushr 8) and 0xFF)
        write(v and 0xFF)
    }
    fun u24(v: Int) {
        write((v ushr 16) and 0xFF)
        u16(v)
    }
    fun bytes(b: ByteArray) = write(b, 0, b.size)
}
