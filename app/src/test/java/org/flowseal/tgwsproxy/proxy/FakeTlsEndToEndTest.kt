package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.flowseal.tgwsproxy.proxy.FakeTls.GROUP_X25519MLKEM768
import org.flowseal.tgwsproxy.proxy.Tls.SECRET
import org.flowseal.tgwsproxy.proxy.Tls.serverHelloFields
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * accept() over loopback sockets against a client that speaks Fake TLS the way Telegram's own
 * clients do (tdlib's TlsInit / tdesktop's TlsSocket): a Chrome-shaped ClientHello signed with the
 * secret, the same checks of the answer, then CCS and ApplicationData records carrying MTProto.
 */
class FakeTlsEndToEndTest {

    private lateinit var ctx: ProxyContext

    @Before
    fun setUp() {
        ctx = ProxyContext(ProxySettings())
        FakeTls.replayCache.clear()
        FakeTls.profiledAppdataLen = null
    }

    @After
    fun tearDown() {
        ctx.shutdown()
        FakeTls.replayCache.clear()
    }

    /** tdlib's Chrome-like ClientHello grammar, with fixed GREASE values and random keys. */
    /** Reads the answer to [hello] and checks it as tdlib's TlsInit::wait_hello_response does. */
    private fun readServerHello(input: InputStream, hello: ByteArray, secret: ByteArray): ByteArray {
        val response = ByteArrayOutputStream()
        for (prefix in listOf("160303", "140303000101170303")) {
            val p = input.readExactly(prefix.length / 2 + 2)
            assertEquals(prefix, Bytes.toHex(p.copyOf(prefix.length / 2)))
            response.write(p)
            response.write(input.readExactly(Bytes.u16be(p, p.size - 2)))
        }
        val bytes = response.toByteArray()
        val zeroed = bytes.copyOf()
        java.util.Arrays.fill(zeroed, 11, 43, 0)
        val clientRandom = hello.copyOfRange(11, 43)
        assertArrayEquals("server random is the HMAC over the flight",
            Bytes.hmacSha256(secret, clientRandom + zeroed), bytes.copyOfRange(11, 43))
        return bytes
    }

    /** A client's 64-byte obfuscated init for [secret] (as MtProtoTest builds it). */
    private fun obfuscatedInit(secret: ByteArray, tag: ByteArray, dcIdx: Int): ByteArray {
        val rnd = Bytes.random(64)
        System.arraycopy(tag, 0, rnd, 56, 4)
        rnd[60] = (dcIdx and 0xFF).toByte()
        rnd[61] = ((dcIdx shr 8) and 0xFF).toByte()
        val encrypted = AesCtr(Bytes.sha256(rnd.copyOfRange(8, 40), secret), rnd.copyOfRange(40, 56)).update(rnd)
        val init = rnd.copyOf()
        System.arraycopy(encrypted, 56, init, 56, 8)
        return init
    }

    private class Outcome {
        val handshake = AtomicReference<MtProto.Handshake?>()
        val accepted = AtomicReference<Boolean?>()
        val error = AtomicReference<Throwable?>()
    }

    /** The proxy side for one connection: accept(), then the MTProto init, then echo one message reversed. */
    private fun serveOne(server: ServerSocket, maskingPort: Int, soTimeoutMs: Int = 10_000): Pair<Thread, Outcome> {
        val outcome = Outcome()
        val t = Thread {
            try {
                server.accept().use { s ->
                    s.soTimeout = soTimeoutMs
                    val input = s.getInputStream()
                    val output = s.getOutputStream()
                    val first = input.read()
                    assertEquals(FakeTls.TLS_RECORD_HANDSHAKE, first)
                    val streams = FakeTls.accept(first, input, output, SECRET, "127.0.0.1", "e2e", ctx, maskingPort)
                    outcome.accepted.set(streams != null)
                    if (streams == null) return@use
                    val (tin, tout) = streams
                    outcome.handshake.set(MtProto.tryHandshake(tin.readExactly(MtConst.HANDSHAKE_LEN), SECRET))
                    val len = Bytes.u16be(tin.readExactly(2), 0) shl 8 or (tin.read() and 0xFF)
                    tout.write(Bytes.reversed(tin.readExactly(len)))
                    tout.flush()
                }
            } catch (e: Throwable) {
                outcome.error.set(e)
            }
        }
        t.start()
        return t to outcome
    }

    private fun loopbackServer() = ServerSocket(0, 50, InetAddress.getLoopbackAddress())

    @Test
    fun telegramClientCompletesHandshakeAndExchangesData() {
        val dead = loopbackServer().also { it.close() }
        loopbackServer().use { server ->
            val (thread, outcome) = serveOne(server, dead.localPort)
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { c ->
                c.soTimeout = 10_000
                val hello = Tls.telegramClientHello("example.com", SECRET)
                val out = c.getOutputStream()
                out.write(hello)
                out.flush()

                val flight = readServerHello(c.getInputStream(), hello, SECRET)
                val records = Tls.splitRecords(flight)
                val (cipher, extensions) = serverHelloFields(records[0].second)
                assertEquals(0x1301, cipher)
                assertEquals(GROUP_X25519MLKEM768, Bytes.u16be(extensions[1].second, 0))
                assertArrayEquals(hello.copyOfRange(44, 76), flight.copyOfRange(44, 76))
                assertTrue(records[2].second.size in FakeTls.FALLBACK_APPDATA_RANGE)

                // Telegram sends one CCS before its first ApplicationData record
                val message = Bytes.random(30_000)
                val payload = obfuscatedInit(SECRET, MtConst.PROTO_TAG_SECURE, -4) +
                    byteArrayOf((message.size ushr 16).toByte(), (message.size ushr 8).toByte(), message.size.toByte()) +
                    message
                out.write(byteArrayOf(0x14, 0x03, 0x03, 0x00, 0x01, 0x01))
                out.write(FakeTls.wrapTlsRecord(payload, 0, 64))
                out.write(FakeTls.wrapTlsRecord(payload, 64, payload.size - 64))
                out.flush()

                val echoed = FakeTlsInputStream(c.getInputStream()).readExactly(message.size)
                assertArrayEquals(Bytes.reversed(message), echoed)
            }
            thread.join(5000)
            assertNull(outcome.error.get())
            assertEquals(true, outcome.accepted.get())
            val hs = outcome.handshake.get()
            assertNotNull(hs)
            assertEquals(4, hs!!.dc)
            assertTrue(hs.isMedia)
            assertArrayEquals(MtConst.PROTO_TAG_SECURE, hs.protoTag)
            assertEquals(0L, ctx.stats.connectionsMasked.get())
        }
    }

    /** A masking site that reads the ClientHello record and a 4-byte "PING", then answers and closes. */
    private fun maskingSite(server: ServerSocket, answer: ByteArray, got: AtomicReference<ByteArray>): Thread =
        Thread {
            try {
                server.accept().use { s ->
                    s.soTimeout = 10_000
                    val input = s.getInputStream()
                    val header = input.readExactly(5)
                    got.set(header + input.readExactly(Bytes.u16be(header, 3)) + input.readExactly(4))
                    s.getOutputStream().apply { write(answer); flush() }
                }
            } catch (_: Exception) {
            }
        }.apply { start() }

    @Test
    fun wrongSecretIsRelayedToTheMaskingSiteBothWays() {
        val answer = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".toByteArray()
        loopbackServer().use { site ->
            val got = AtomicReference<ByteArray>()
            val siteThread = maskingSite(site, answer, got)
            loopbackServer().use { server ->
                // a short client read timeout must not end the masking relay
                val (thread, outcome) = serveOne(server, site.localPort, soTimeoutMs = 150)
                Socket(InetAddress.getLoopbackAddress(), server.localPort).use { c ->
                    c.soTimeout = 10_000
                    val hello = Tls.telegramClientHello("example.com", Bytes.fromHex("ffeeddccbbaa99887766554433221100"))
                    val out = c.getOutputStream()
                    out.write(hello)
                    out.flush()
                    Thread.sleep(400)
                    out.write("PING".toByteArray())
                    out.flush()
                    assertArrayEquals(answer, c.getInputStream().readBytes())
                    assertArrayEquals(hello + "PING".toByteArray(), got.get())
                }
                thread.join(5000)
                assertTrue(!thread.isAlive)
                assertNull(outcome.error.get())
                assertEquals(false, outcome.accepted.get())
            }
            siteThread.join(5000)
        }
        assertEquals(1L, ctx.stats.connectionsMasked.get())
    }

    @Test
    fun replayedHelloOverTheWireIsMasked() {
        val answer = "masked".toByteArray()
        loopbackServer().use { site ->
            val got = AtomicReference<ByteArray>()
            maskingSite(site, answer, got)
            loopbackServer().use { server ->
                val hello = Tls.telegramClientHello("example.com", SECRET)

                val (t1, o1) = serveOne(server, site.localPort)
                Socket(InetAddress.getLoopbackAddress(), server.localPort).use { c ->
                    c.soTimeout = 10_000
                    c.getOutputStream().write(hello)
                    readServerHello(c.getInputStream(), hello, SECRET)
                }
                t1.join(5000)
                assertEquals(true, o1.accepted.get())

                val (t2, o2) = serveOne(server, site.localPort)
                Socket(InetAddress.getLoopbackAddress(), server.localPort).use { c ->
                    c.soTimeout = 10_000
                    c.getOutputStream().apply { write(hello); write("PING".toByteArray()); flush() }
                    assertArrayEquals(answer, c.getInputStream().readBytes())
                }
                t2.join(5000)
                assertEquals(false, o2.accepted.get())
                assertArrayEquals(hello + "PING".toByteArray(), got.get())
            }
        }
        assertEquals(1L, ctx.stats.connectionsMasked.get())
    }

    @Test
    fun serverHelloIsDelayed() {
        val dead = loopbackServer().also { it.close() }
        loopbackServer().use { server ->
            val (thread, _) = serveOne(server, dead.localPort)
            Socket(InetAddress.getLoopbackAddress(), server.localPort).use { c ->
                c.soTimeout = 10_000
                val hello = Tls.telegramClientHello("example.com", SECRET)
                val start = System.nanoTime()
                c.getOutputStream().write(hello)
                readServerHello(c.getInputStream(), hello, SECRET)
                val elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start)
                assertTrue("answered after $elapsedMs ms", elapsedMs >= 8)
            }
            thread.join(5000)
        }
    }
}
