package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.math.BigInteger
import java.net.InetAddress
import java.net.ServerSocket
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.cert.CertificateFactory
import java.text.SimpleDateFormat
import java.util.Collections
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket
import org.flowseal.tgwsproxy.proxy.FakeTls.APPDATA_MIN
import org.flowseal.tgwsproxy.proxy.FakeTls.CLIENT_RANDOM_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.EXT_KEY_SHARE
import org.flowseal.tgwsproxy.proxy.FakeTls.EXT_SUPPORTED_VERSIONS
import org.flowseal.tgwsproxy.proxy.FakeTls.FALLBACK_APPDATA_RANGE
import org.flowseal.tgwsproxy.proxy.FakeTls.GROUP_X25519
import org.flowseal.tgwsproxy.proxy.FakeTls.GROUP_X25519MLKEM768
import org.flowseal.tgwsproxy.proxy.FakeTls.MLKEM768_CIPHERTEXT_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.SESSION_ID_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.SESSION_ID_OFFSET
import org.flowseal.tgwsproxy.proxy.FakeTls.TIMESTAMP_TOLERANCE
import org.flowseal.tgwsproxy.proxy.FakeTls.TLS_APPDATA_MAX
import org.flowseal.tgwsproxy.proxy.FakeTls.TLS_RECORD_APPDATA
import org.flowseal.tgwsproxy.proxy.FakeTls.TLS_RECORD_CCS
import org.flowseal.tgwsproxy.proxy.FakeTls.TLS_RECORD_HANDSHAKE
import org.flowseal.tgwsproxy.proxy.FakeTls.X25519_KEY_LEN
import org.flowseal.tgwsproxy.proxy.FakeTls.buildServerHello
import org.flowseal.tgwsproxy.proxy.FakeTls.firstAppdataRecordLen
import org.flowseal.tgwsproxy.proxy.FakeTls.parseClientHello
import org.flowseal.tgwsproxy.proxy.FakeTls.probeAppdataLen
import org.flowseal.tgwsproxy.proxy.FakeTls.verifyClientHello
import org.flowseal.tgwsproxy.proxy.FakeTls.wrapTlsRecord
import org.flowseal.tgwsproxy.proxy.Tls.SECRET
import org.flowseal.tgwsproxy.proxy.Tls.TELEGRAM_SHARES
import org.flowseal.tgwsproxy.proxy.Tls.TELEGRAM_SUITES
import org.flowseal.tgwsproxy.proxy.Tls.clientHello
import org.flowseal.tgwsproxy.proxy.Tls.record
import org.flowseal.tgwsproxy.proxy.Tls.serverHelloFields
import org.flowseal.tgwsproxy.proxy.Tls.splitRecords
import org.flowseal.tgwsproxy.proxy.Tls.structuredClientHello
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** Port of upstream tests/test_fake_tls.py, plus the stream classes. */
class FakeTlsTest {

    // ---- VerifyClientHelloTest ----

    @Test
    fun acceptsWellFormedHello() {
        val sessionId = Bytes.random(SESSION_ID_LEN)
        val now = Tls.nowSeconds()
        val result = verifyClientHello(clientHello(timestamp = now, sessionId = sessionId), SECRET)
        assertNotNull(result)
        assertEquals(CLIENT_RANDOM_LEN, result!!.clientRandom.size)
        assertArrayEquals(sessionId, result.sessionId)
        assertEquals(now, result.timestamp)
    }

    @Test
    fun rejectsWrongSecret() {
        val other = Bytes.fromHex("ffeeddccbbaa99887766554433221100")
        assertNull(verifyClientHello(clientHello(), other))
    }

    @Test
    fun rejectsStaleTimestamp() {
        val stale = Tls.nowSeconds() - 3600
        assertNull(verifyClientHello(clientHello(timestamp = stale), SECRET))
    }

    @Test
    fun timestampToleranceIsInclusive() {
        val ts = 1_800_000_000L
        val hello = clientHello(timestamp = ts)
        for (delta in listOf(-TIMESTAMP_TOLERANCE, 0, TIMESTAMP_TOLERANCE)) {
            assertNotNull("delta $delta", verifyClientHello(hello, SECRET, (ts + delta) * 1000))
        }
        assertNotNull(verifyClientHello(hello, SECRET, (ts + TIMESTAMP_TOLERANCE) * 1000 + 999))
        assertNull(verifyClientHello(hello, SECRET, (ts - TIMESTAMP_TOLERANCE - 1) * 1000))
        assertNull(verifyClientHello(hello, SECRET, (ts + TIMESTAMP_TOLERANCE + 1) * 1000))
    }

    @Test
    fun rejectsTamperedBody() {
        val hello = clientHello()
        hello[300] = (hello[300].toInt() xor 0xFF).toByte()
        assertNull(verifyClientHello(hello, SECRET))
    }

    @Test
    fun rejectsShortAndNonHandshakeRecords() {
        assertNull(verifyClientHello(byteArrayOf(0x16, 0x03, 0x01, 0x00, 0x10), SECRET))
        var hello = clientHello()
        hello[0] = 0x17
        assertNull(verifyClientHello(hello, SECRET))
        hello = clientHello()
        hello[5] = 0x02
        assertNull(verifyClientHello(hello, SECRET))
    }

    @Test
    fun missingSessionIdGivesZeros() {
        val body = ByteArray(100)
        body[0] = 0x16; body[1] = 0x03; body[2] = 0x01; body[4] = 95; body[5] = 0x01
        val result = verifyClientHello(Tls.sign(body, SECRET, Tls.nowSeconds()), SECRET)
        assertArrayEquals(ByteArray(SESSION_ID_LEN), result!!.sessionId)
    }

    // ---- ParseClientHelloTest ----

    @Test
    fun extractsSuitesAndKeyShares() {
        val info = parseClientHello(structuredClientHello())
        assertEquals(TELEGRAM_SUITES.toSet(), info.cipherSuites)
        assertEquals(TELEGRAM_SHARES.toMap(), info.keyShares)
    }

    @Test
    fun structuredHelloStillVerifies() {
        assertNotNull(verifyClientHello(structuredClientHello(), SECRET))
    }

    @Test
    fun malformedHelloYieldsEmptyInfo() {
        assertEquals(ClientHelloInfo.EMPTY, parseClientHello(byteArrayOf(0x16, 0x03, 0x01, 0x00)))
        val truncated = structuredClientHello().copyOf(60)
        assertEquals(ClientHelloInfo.EMPTY, parseClientHello(truncated))
    }

    @Test
    fun unstructuredHelloDoesNotThrow() {
        parseClientHello(clientHello())
    }

    @Test
    fun firstKeyShareOfAGroupWins() {
        val info = parseClientHello(
            structuredClientHello(shares = listOf(GROUP_X25519 to 32, GROUP_X25519 to 16)),
        )
        assertEquals(mapOf(GROUP_X25519 to 32), info.keyShares)
    }

    // ---- BuildServerHelloTest ----

    @Before
    fun resetProfile() {
        FakeTls.profiledAppdataLen = null
        FakeTls.replayCache.clear()
    }

    @After
    fun cleanUp() {
        FakeTls.profiledAppdataLen = null
        FakeTls.replayCache.clear()
    }

    private fun build(hello: ByteArray, clientRandom: ByteArray = Bytes.random(CLIENT_RANDOM_LEN)): ByteArray =
        buildServerHello(SECRET, clientRandom, Bytes.random(SESSION_ID_LEN), parseClientHello(hello))

    @Test
    fun flightIsServerHelloCcsAndOneAppdataRecord() {
        val records = splitRecords(build(structuredClientHello()))
        assertEquals(listOf(TLS_RECORD_HANDSHAKE, TLS_RECORD_CCS, TLS_RECORD_APPDATA), records.map { it.first })
        assertArrayEquals(byteArrayOf(0x01), records[1].second)
    }

    @Test
    fun hmacCoversWholeFlight() {
        val clientRandom = Bytes.random(CLIENT_RANDOM_LEN)
        val response = build(structuredClientHello(), clientRandom)
        val zeroed = response.copyOf()
        java.util.Arrays.fill(zeroed, 11, 43, 0)
        val expected = Bytes.hmacSha256(SECRET, clientRandom + zeroed)
        assertArrayEquals(expected, response.copyOfRange(11, 43))
    }

    @Test
    fun mirrorsPostQuantumGroupWhenOffered() {
        val records = splitRecords(build(structuredClientHello()))
        val (cipher, extensions) = serverHelloFields(records[0].second)
        assertEquals(listOf(EXT_SUPPORTED_VERSIONS, EXT_KEY_SHARE), extensions.map { it.first })
        val keyShare = extensions[1].second
        assertEquals(GROUP_X25519MLKEM768, Bytes.u16be(keyShare, 0))
        val length = Bytes.u16be(keyShare, 2)
        assertEquals(MLKEM768_CIPHERTEXT_LEN + X25519_KEY_LEN, length)
        assertEquals(4 + length, keyShare.size)
        assertEquals(0x1301, cipher)
        // the X25519 half is a real public key, below 2^255
        assertEquals(0, keyShare[keyShare.size - 1].toInt() and 0x80)
    }

    @Test
    fun fallsBackToX25519() {
        val hello = structuredClientHello(shares = listOf(GROUP_X25519 to X25519_KEY_LEN))
        val records = splitRecords(build(hello))
        val (_, extensions) = serverHelloFields(records[0].second)
        val keyShare = extensions[1].second
        assertEquals(GROUP_X25519 to X25519_KEY_LEN, Bytes.u16be(keyShare, 0) to Bytes.u16be(keyShare, 2))
        // real X25519 public keys are below 2^255
        assertEquals(0, keyShare[keyShare.size - 1].toInt() and 0x80)
    }

    @Test
    fun ignoresPostQuantumShareOfWrongSize() {
        val hello = structuredClientHello(
            shares = listOf(GROUP_X25519MLKEM768 to 100, GROUP_X25519 to X25519_KEY_LEN),
        )
        val (_, extensions) = serverHelloFields(splitRecords(build(hello))[0].second)
        assertEquals(GROUP_X25519, Bytes.u16be(extensions[1].second, 0))
    }

    @Test
    fun picksCipherOfferedByClient() {
        val hello = structuredClientHello(suites = listOf(0x1302, 0x1303))
        val (cipher, _) = serverHelloFields(splitRecords(build(hello))[0].second)
        assertEquals(0x1303, cipher)
        val only1302 = structuredClientHello(suites = listOf(0x1302))
        assertEquals(0x1302, serverHelloFields(splitRecords(build(only1302))[0].second).first)
        val none = structuredClientHello(suites = listOf(0xc02b))
        assertEquals(0x1301, serverHelloFields(splitRecords(build(none))[0].second).first)
    }

    @Test
    fun telegramFlightMatchesTelemtSize() {
        // telemt answered every Telegram client with exactly 1290 bytes when the masking site's
        // first encrypted record was below the 64-byte floor
        FakeTls.profiledAppdataLen = 30
        assertEquals(1290, build(structuredClientHello()).size)
    }

    @Test
    fun usesProfiledAppdataLen() {
        FakeTls.profiledAppdataLen = 3000
        val records = splitRecords(build(structuredClientHello()))
        assertEquals(3000, records[2].second.size)
    }

    @Test
    fun profiledLenIsClamped() {
        FakeTls.profiledAppdataLen = 10
        assertEquals(APPDATA_MIN, FakeTls.profiledAppdataLen)
        FakeTls.profiledAppdataLen = 1_000_000
        assertEquals(TLS_APPDATA_MAX, FakeTls.profiledAppdataLen)
        FakeTls.profiledAppdataLen = null
        assertNull(FakeTls.profiledAppdataLen)
    }

    @Test
    fun fallbackLenStaysInRange() {
        repeat(20) {
            val records = splitRecords(build(structuredClientHello()))
            assertTrue(records[2].second.size in FALLBACK_APPDATA_RANGE)
        }
    }

    @Test
    fun echoesSessionIdAndBindsClientRandom() {
        val sessionId = Bytes.random(SESSION_ID_LEN)
        val clientRandom = Bytes.random(CLIENT_RANDOM_LEN)
        val response = buildServerHello(SECRET, clientRandom, sessionId)

        assertEquals(TLS_RECORD_HANDSHAKE, response[0].toInt())
        assertArrayEquals(sessionId, response.copyOfRange(SESSION_ID_OFFSET, SESSION_ID_OFFSET + SESSION_ID_LEN))

        val zeroed = response.copyOf()
        java.util.Arrays.fill(zeroed, 11, 43, 0)
        assertArrayEquals(Bytes.hmacSha256(SECRET, clientRandom + zeroed), response.copyOfRange(11, 43))
    }

    @Test
    fun paddingLengthVariesBetweenCalls() {
        val sizes = (0 until 20).map {
            buildServerHello(SECRET, Bytes.random(32), Bytes.random(32)).size
        }.toSet()
        assertTrue(sizes.size > 1)
    }

    // ---- FirstAppdataRecordLenTest ----

    @Test
    fun findsRecordAfterServerHelloAndCcs() {
        val flight = record(TLS_RECORD_HANDSHAKE, 122) + record(TLS_RECORD_CCS, 1) +
            record(TLS_RECORD_APPDATA, 27) + record(TLS_RECORD_APPDATA, 3000)
        assertEquals(27, firstAppdataRecordLen(flight))
    }

    @Test
    fun needsMoreDataUntilHeaderArrives() {
        val partial = record(TLS_RECORD_HANDSHAKE, 122) + record(TLS_RECORD_CCS, 1)
        assertNull(firstAppdataRecordLen(partial))
        assertNull(firstAppdataRecordLen(partial + byteArrayOf(0x17, 0x03)))
    }

    @Test
    fun alertMeansNoProfile() {
        assertEquals(0, firstAppdataRecordLen(record(0x15, 2)))
    }

    // ---- ProbeAppdataLenTest (loopback only) ----

    private fun readRecord(input: InputStream): ByteArray {
        val header = input.readExactly(5)
        return header + input.readExactly(Bytes.u16be(header, 3))
    }

    @Test
    fun continuousRecordsDoNotExtendProbeTimeout() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val writes = AtomicInteger()
        val serverDone = CountDownLatch(1)
        val t = Thread {
            try {
                server.accept().use { s ->
                    readRecord(s.getInputStream())
                    val out = s.getOutputStream()
                    while (true) {
                        Thread.sleep(10)
                        out.write(record(TLS_RECORD_CCS, 1))
                        out.flush()
                        writes.incrementAndGet()
                    }
                }
            } catch (_: Exception) {
            } finally {
                serverDone.countDown()
            }
        }
        t.start()
        try {
            val start = System.nanoTime()
            val result = probeAppdataLen("127.0.0.1", server.localPort, timeoutMs = 100)
            val elapsedMs = (System.nanoTime() - start) / 1_000_000
            assertNull(result)
            assertTrue("took $elapsedMs ms", elapsedMs < 2000)
            assertTrue(writes.get() > 1)
            // the probe closed its socket, so the server's writes start failing
            assertTrue(serverDone.await(2, TimeUnit.SECONDS))
        } finally {
            server.close()
        }
    }

    @Test
    fun silentServerObeysProbeTimeout() {
        val loopback = InetAddress.getByName("localhost")
        val server = ServerSocket(0, 50, loopback)
        val hello = AtomicReference<ByteArray>()
        val sawEof = CountDownLatch(1)
        val t = Thread {
            try {
                server.accept().use { s ->
                    val input = s.getInputStream()
                    hello.set(readRecord(input))
                    if (input.read() < 0) sawEof.countDown()
                }
            } catch (_: Exception) {
            }
        }
        t.start()
        try {
            val start = System.nanoTime()
            assertNull(probeAppdataLen("localhost", server.localPort, timeoutMs = 100))
            assertTrue((System.nanoTime() - start) / 1_000_000 < 2000)
            assertTrue(sawEof.await(2, TimeUnit.SECONDS))
        } finally {
            server.close()
        }
        val sent = hello.get()
        val info = parseClientHello(sent)
        assertEquals(mapOf(GROUP_X25519 to X25519_KEY_LEN), info.keyShares)
        assertEquals(setOf(0x1301, 0x1302, 0x1303, 0x00ff), info.cipherSuites)
        assertTrue("SNI carries the domain", String(sent, Charsets.ISO_8859_1).contains("localhost"))
    }

    @Test
    fun probeHelloHasNoSniForIpAddresses() {
        val hello = FakeTls.buildProbeClientHello("127.0.0.1")
        assertFalse(String(hello, Charsets.ISO_8859_1).contains("127.0.0.1"))
        assertEquals(hello.size - 5, Bytes.u16be(hello, 3))
        assertEquals(0x01, hello[5].toInt())
    }

    @Test
    fun measuresFirstEncryptedRecordOfRealTls13Server() {
        val server = selfSignedTls13Server()
        val t = Thread {
            try {
                (server.accept() as SSLSocket).use { it.startHandshake() }
            } catch (_: Exception) {
            }
        }
        t.start()
        try {
            val length = probeAppdataLen("127.0.0.1", server.localPort, timeoutMs = 3000)
            assertNotNull(length)
            assertTrue(length!! > 0)
        } finally {
            server.close()
        }
    }

    @Test
    fun unreachableSiteGivesNoProfile() {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val port = server.localPort
        server.close()
        assertNull(probeAppdataLen("127.0.0.1", port, timeoutMs = 1000))
    }

    @Test
    fun profileMaskingSiteResetsAndStoresTheProfile() {
        FakeTls.profiledAppdataLen = 500
        assertNull(FakeTls.profileMaskingSite(""))
        assertNull(FakeTls.profiledAppdataLen)
    }

    // ---- WrapTlsRecordTest ----

    @Test
    fun shortPayloadBecomesOneRecord() {
        val wrapped = wrapTlsRecord("hello".toByteArray())
        assertArrayEquals(byteArrayOf(0x17, 0x03, 0x03, 0x00, 0x05) + "hello".toByteArray(), wrapped)
    }

    @Test
    fun longPayloadIsChunkedToTheRecordLimit() {
        val payload = Bytes.random(TLS_APPDATA_MAX + 100)
        val wrapped = wrapTlsRecord(payload)
        val chunks = splitRecords(wrapped)
        chunks.forEach { assertTrue(it.second.size <= TLS_APPDATA_MAX) }
        assertEquals(2, chunks.size)
        assertArrayEquals(payload, chunks.fold(ByteArray(0)) { acc, c -> acc + c.second })
    }

    @Test
    fun emptyPayloadProducesNoRecords() {
        assertEquals(0, wrapTlsRecord(ByteArray(0)).size)
    }

    // ---- ReplayCacheTest ----

    private fun key(s: String) = s.toByteArray()

    @Test
    fun secondSightingWithinWindowIsAReplay() {
        val cache = ReplayCache(windowMs = 10_000, maxSize = 8)
        assertTrue(cache.firstSeen(key("a")))
        assertFalse(cache.firstSeen(key("a")))
        assertTrue(cache.firstSeen(key("b")))
    }

    @Test
    fun entriesExpireAfterTheWindow() {
        var now = 100_000L
        val cache = ReplayCache(windowMs = 10_000, maxSize = 8, clockMs = { now })
        cache.firstSeen(key("a"))
        now = 110_000L
        assertTrue(cache.firstSeen(key("a")))
    }

    @Test
    fun sizeIsBoundedByDroppingOldest() {
        val cache = ReplayCache(windowMs = 10_000, maxSize = 2)
        for (k in listOf("a", "b", "c")) cache.firstSeen(key(k))
        assertEquals(2, cache.size)
        assertTrue(cache.firstSeen(key("a")))
    }

    @Test
    fun windowCoversTheWholeTimestampTolerance() {
        assertTrue(FakeTls.REPLAY_WINDOW_MS >= 2L * TIMESTAMP_TOLERANCE * 1000)
    }

    @Test
    fun repeatInAFullCacheIsStillAReplay() {
        val cache = ReplayCache(windowMs = 10_000, maxSize = 2)
        cache.firstSeen(key("a"))
        cache.firstSeen(key("b"))
        assertFalse("a live entry must not be evicted before the lookup", cache.firstSeen(key("a")))
        assertFalse(cache.firstSeen(key("b")))
    }

    @Test
    fun fullCacheEvictsTheOldestEntryForANewKey() {
        val cache = ReplayCache(windowMs = 10_000, maxSize = 2)
        for (k in listOf("a", "b", "c")) assertTrue(cache.firstSeen(key(k)))
        assertEquals(listOf("b", "c"), cache.keys().map { String(it) })
        assertFalse(cache.firstSeen(key("b")))
        assertFalse(cache.firstSeen(key("c")))
    }

    @Test
    fun entryIsStillAReplayJustBeforeExpiry() {
        var now = 100_000L
        val cache = ReplayCache(windowMs = 10_000, maxSize = 8, clockMs = { now })
        cache.firstSeen(key("a"))
        now = 109_999L
        assertFalse(cache.firstSeen(key("a")))
    }

    @Test
    fun replayIsRefusedForAsLongAsTheHelloVerifies() {
        // The earliest and latest moments one hello passes the timestamp check, with
        // verifyClientHello() truncating wall time to whole seconds
        val ts = 1_800_000_000L
        val hello = clientHello(timestamp = ts)
        var now = 0L
        val cache = ReplayCache(clockMs = { now })

        now = (ts - TIMESTAMP_TOLERANCE) * 1000
        val first = verifyClientHello(hello, SECRET, now)
        assertNotNull(first)
        assertTrue(cache.firstSeen(first!!.clientRandom))

        now = (ts + TIMESTAMP_TOLERANCE) * 1000 + 999
        val replayed = verifyClientHello(hello, SECRET, now)
        assertNotNull("the hello still passes the timestamp check", replayed)
        assertFalse("so the cache must still refuse it", cache.firstSeen(replayed!!.clientRandom))
    }

    @Test
    fun keyIsNewAgainAfterTheWindow() {
        var now = 100_000L
        val cache = ReplayCache(windowMs = 10_000, maxSize = 8, clockMs = { now })
        cache.firstSeen(key("a"))
        now = 111_000L
        assertTrue(cache.firstSeen(key("a")))
        assertFalse(cache.firstSeen(key("a")))
    }

    // ---- ReplayedHelloTest: accept() with a local stand-in for the masking site ----

    /** Accepts connections and records everything each one sends until EOF. */
    private class FakeMaskingSite : AutoCloseable {
        val server = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val received: MutableList<ByteArray> = Collections.synchronizedList(ArrayList())
        private val thread = Thread {
            try {
                while (true) {
                    server.accept().use { s -> received.add(s.getInputStream().readBytes()) }
                }
            } catch (_: IOException) {
            }
        }.apply { isDaemon = true; start() }

        val port: Int get() = server.localPort

        override fun close() = server.close()
    }

    private fun handshake(
        hello: ByteArray,
        site: FakeMaskingSite,
        ctx: ProxyContext,
        init: ByteArray,
    ): Pair<Pair<InputStream, OutputStream>?, ByteArray> {
        val input = ByteArrayInputStream(hello + wrapTlsRecord(init))
        val output = ByteArrayOutputStream()
        val first = input.read()
        val result = FakeTls.accept(first, input, output, SECRET, "127.0.0.1", "test", ctx, site.port)
        return result to output.toByteArray()
    }

    @Test
    fun replayedHelloIsMaskedInsteadOfAnswered() {
        val ctx = ProxyContext(ProxySettings())
        FakeMaskingSite().use { site ->
            try {
                val hello = structuredClientHello()
                val init = Bytes.random(64)
                val (first, firstWritten) = handshake(hello, site, ctx, init)
                assertNotNull(first)
                assertEquals(TLS_RECORD_HANDSHAKE, firstWritten[0].toInt())
                assertArrayEquals(init, first!!.first.readExactly(64))
                assertEquals(0L, ctx.stats.connectionsMasked.get())
                assertEquals(0, site.received.size)

                val (second, secondWritten) = handshake(hello, site, ctx, init)
                assertNull(second)
                assertEquals(0, secondWritten.size)
                assertEquals(1L, ctx.stats.connectionsMasked.get())
                waitFor { site.received.size == 1 }
                assertArrayEquals(hello + wrapTlsRecord(init), site.received[0])
            } finally {
                ctx.shutdown()
            }
        }
    }

    @Test
    fun wrongSecretIsMasked() {
        val ctx = ProxyContext(ProxySettings())
        FakeMaskingSite().use { site ->
            try {
                val hello = structuredClientHello(secret = Bytes.fromHex("ffeeddccbbaa99887766554433221100"))
                val (result, written) = handshake(hello, site, ctx, Bytes.random(64))
                assertNull(result)
                assertEquals(0, written.size)
                assertEquals(1L, ctx.stats.connectionsMasked.get())
                waitFor { site.received.size == 1 }
                assertArrayEquals(hello, site.received[0].copyOf(hello.size))
            } finally {
                ctx.shutdown()
            }
        }
    }

    @Test
    fun truncatedHelloIsDropped() {
        val ctx = ProxyContext(ProxySettings())
        try {
            val hello = structuredClientHello()
            val input = ByteArrayInputStream(hello.copyOf(200))
            val output = ByteArrayOutputStream()
            assertNull(FakeTls.accept(input.read(), input, output, SECRET, "127.0.0.1", "t", ctx, 1))
            assertEquals(0, output.size())
            assertEquals(0L, ctx.stats.connectionsMasked.get())
        } finally {
            ctx.shutdown()
        }
    }

    @Test
    fun unreachableMaskingSiteEndsQuietly() {
        val ctx = ProxyContext(ProxySettings())
        val dead = ServerSocket(0, 50, InetAddress.getLoopbackAddress())
        val port = dead.localPort
        dead.close()
        try {
            val input = ByteArrayInputStream(clientHello(secret = ByteArray(16)))
            val output = ByteArrayOutputStream()
            assertNull(FakeTls.accept(input.read(), input, output, SECRET, "127.0.0.1", "t", ctx, port))
            assertEquals(0L, ctx.stats.connectionsMasked.get())
        } finally {
            ctx.shutdown()
        }
    }

    // ---- Record streams ----

    @Test
    fun inputStreamUnwrapsRecordsAndSkipsCcs() {
        val a = Bytes.random(10)
        val b = Bytes.random(20000)
        val wire = record(TLS_RECORD_CCS, 1, byteArrayOf(1)) + wrapTlsRecord(a) +
            record(TLS_RECORD_APPDATA, 0) + wrapTlsRecord(b) + record(TLS_RECORD_CCS, 1, byteArrayOf(1))
        val input = FakeTlsInputStream(ByteArrayInputStream(wire))
        assertArrayEquals(a + b, input.readExactly(a.size + b.size))
        assertEquals(-1, input.read())
        assertEquals(-1, input.read(ByteArray(4)))
    }

    @Test
    fun inputStreamReadsNeverCrossTheCallersLength() {
        val payload = Bytes.random(100)
        val input = FakeTlsInputStream(ByteArrayInputStream(wrapTlsRecord(payload)))
        val out = ByteArrayOutputStream()
        val buf = ByteArray(7)
        while (true) {
            val n = input.read(buf)
            if (n < 0) break
            assertTrue(n in 1..7)
            out.write(buf, 0, n)
        }
        assertArrayEquals(payload, out.toByteArray())
    }

    @Test
    fun inputStreamEndsAtAnAlert() {
        val wire = wrapTlsRecord(byteArrayOf(1, 2, 3)) + record(0x15, 2, byteArrayOf(1, 0)) + wrapTlsRecord(byteArrayOf(9))
        val input = FakeTlsInputStream(ByteArrayInputStream(wire))
        assertArrayEquals(byteArrayOf(1, 2, 3), input.readExactly(3))
        assertEquals(-1, input.read())
        assertEquals(-1, input.read())
    }

    @Test
    fun inputStreamTruncatedRecordIsEof() {
        val wire = wrapTlsRecord(Bytes.random(50)).copyOf(30)
        val input = FakeTlsInputStream(ByteArrayInputStream(wire))
        assertEquals(25, input.readBytes().size)
    }

    @Test(expected = java.io.EOFException::class)
    fun inputStreamTornHeaderThrows() {
        FakeTlsInputStream(ByteArrayInputStream(byteArrayOf(0x17, 0x03))).read()
    }

    @Test
    fun outputStreamWrapsEachWrite() {
        val sink = ByteArrayOutputStream()
        val out = FakeTlsOutputStream(sink)
        val big = Bytes.random(TLS_APPDATA_MAX * 2 + 1)
        out.write(byteArrayOf(1, 2, 3))
        out.write(ByteArray(0))
        out.write(7)
        out.write(big, 0, big.size)
        out.flush()
        val records = splitRecords(sink.toByteArray())
        assertEquals(listOf(3, 1, TLS_APPDATA_MAX, TLS_APPDATA_MAX, 1), records.map { it.second.size })
        assertTrue(records.all { it.first == TLS_RECORD_APPDATA })
        assertArrayEquals(
            wrapTlsRecord(byteArrayOf(1, 2, 3)) + wrapTlsRecord(byteArrayOf(7)) + wrapTlsRecord(big),
            sink.toByteArray(),
        )
    }

    @Test
    fun streamsRoundTrip() {
        val sink = ByteArrayOutputStream()
        val payload = Bytes.random(50_000)
        FakeTlsOutputStream(sink).write(payload)
        assertArrayEquals(payload, FakeTlsInputStream(ByteArrayInputStream(sink.toByteArray())).readBytes())
    }

    companion object {
        fun waitFor(timeoutMs: Long = 3000, cond: () -> Boolean) {
            val deadline = System.currentTimeMillis() + timeoutMs
            while (!cond()) {
                if (System.currentTimeMillis() > deadline) throw AssertionError("timed out waiting")
                Thread.sleep(5)
            }
        }

        /** A loopback TLS 1.3-only server with a fresh self-signed ECDSA P-256 certificate. */
        fun selfSignedTls13Server(): SSLServerSocket {
            val kp = KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
            val ecdsaSha256 = der(0x06, Bytes.fromHex("2a8648ce3d040302"))
            val name = seq(der(0x31, seq(der(0x06, Bytes.fromHex("550403")), der(0x0c, "localhost".toByteArray()))))
            val fmt = SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
            val now = System.currentTimeMillis()
            val tbs = seq(
                der(0xa0, der(0x02, byteArrayOf(2))),
                der(0x02, BigInteger.valueOf(now).toByteArray()),
                seq(ecdsaSha256),
                name,
                seq(
                    der(0x17, fmt.format(Date(now - 86_400_000)).toByteArray()),
                    der(0x17, fmt.format(Date(now + 86_400_000)).toByteArray()),
                ),
                name,
                kp.public.encoded,
            )
            val sig = Signature.getInstance("SHA256withECDSA").run {
                initSign(kp.private)
                update(tbs)
                sign()
            }
            val certDer = seq(tbs, seq(ecdsaSha256), der(0x03, byteArrayOf(0) + sig))
            val cert = CertificateFactory.getInstance("X.509").generateCertificate(certDer.inputStream())

            val password = "test".toCharArray()
            val ks = KeyStore.getInstance("PKCS12").apply {
                load(null, null)
                setKeyEntry("k", kp.private, password, arrayOf(cert))
            }
            val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, password) }
            val ssl = SSLContext.getInstance("TLSv1.3").apply { init(kmf.keyManagers, null, null) }
            return (ssl.serverSocketFactory.createServerSocket(0, 50, InetAddress.getLoopbackAddress()) as SSLServerSocket)
                .apply { enabledProtocols = arrayOf("TLSv1.3") }
        }

        private fun der(tag: Int, content: ByteArray): ByteArray {
            val len = content.size
            val lenBytes = when {
                len < 0x80 -> byteArrayOf(len.toByte())
                len < 0x100 -> byteArrayOf(0x81.toByte(), len.toByte())
                else -> byteArrayOf(0x82.toByte(), (len ushr 8).toByte(), len.toByte())
            }
            return byteArrayOf(tag.toByte()) + lenBytes + content
        }

        private fun seq(vararg parts: ByteArray): ByteArray =
            der(0x30, parts.fold(ByteArray(0)) { acc, p -> acc + p })
    }
}
