package org.flowseal.tgwsproxy.proxy

import okhttp3.Dns
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.internal.http2.ErrorCode
import okhttp3.internal.http2.Http2Stream
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import okhttp3.mockwebserver.internal.duplex.DuplexResponseBody
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okio.Buffer
import okio.buffer
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.io.InterruptedIOException
import java.net.InetAddress
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.withLock

/**
 * The OkHttp transport against a real local HTTP/2 server over TLS with ALPN (upstream
 * tests/test_h2_transport.py H2WireTest). No network: the server listens on 127.0.0.1.
 */
class CfH2WireTest {

    private class Exchange(val request: RecordedRequest, val body: ByteArray) {
        val reply = CompletableFuture<MockResponse>()
        val method: String get() = request.method ?: ""
        /** 0 for the first request of a TCP connection. */
        val sequence: Int get() = request.sequenceNumber
    }

    private lateinit var ctx: ProxyContext
    private lateinit var server: MockWebServer
    private lateinit var client: OkHttpClient
    private lateinit var lane: CfH2Lane
    private val requests = LinkedBlockingQueue<Exchange>()
    private val exchanges = CopyOnWriteArrayList<Exchange>()
    private val pools = ArrayList<CfH2Pool>()
    private val extraServers = ArrayList<MockWebServer>()
    @Volatile private var autoHead = true

    private fun startServer(protocols: List<Protocol>): MockWebServer = MockWebServer().apply {
        useHttps(serverCerts.sslSocketFactory(), false)
        this.protocols = protocols
        dispatcher = object : Dispatcher() {
            override fun dispatch(request: RecordedRequest): MockResponse {
                if (autoHead && request.method == "HEAD") return MockResponse().setResponseCode(501)
                val exchange = Exchange(request, request.body.readByteArray())
                exchanges.add(exchange)
                requests.put(exchange)
                return exchange.reply.get(10, TimeUnit.SECONDS)
            }
        }
        start(InetAddress.getByName("127.0.0.1"), 0)
    }

    @Before
    fun setUp() {
        ctx = ProxyContext(ProxySettings(secretHex = "ab".repeat(16)))
        server = startServer(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
        client = OkHttpCfH2Transport.clientBuilder()
            .sslSocketFactory(clientCerts.sslSocketFactory(), clientCerts.trustManager)
            .dns(object : Dns {
                override fun lookup(hostname: String): List<InetAddress> = listOf(InetAddress.getByName("127.0.0.1"))
            })
            .readTimeout(5, TimeUnit.SECONDS)
            .build()
        lane = newLane(server)
    }

    @After
    fun tearDown() {
        for (exchange in exchanges) exchange.reply.complete(MockResponse().setResponseCode(503))
        lane.close()
        for (pool in pools) pool.close()
        for (s in extraServers + server) {
            try {
                s.shutdown()
            } catch (_: IOException) {
            }
        }
        ctx.shutdown()
        ProxyLog.verbose = false
    }

    private fun newLane(target: MockWebServer, okHttp: OkHttpClient = client): CfH2Lane {
        val host = "localhost:${target.port}"
        return CfH2Lane(host, 1, ctx, CfH2Tuning(), OkHttpCfH2Transport(host, okHttp))
    }

    private fun nextRequest(timeoutMs: Long = 2000): Exchange =
        requests.poll(timeoutMs, TimeUnit.MILLISECONDS) ?: throw AssertionError("no request reached the server")

    private fun Exchange.respond(body: ByteArray = rep('r', 40), status: Int = 200, configure: MockResponse.() -> Unit = {}) {
        reply.complete(
            MockResponse().setResponseCode(status).setHeader("content-type", "application/octet-stream")
                .setBody(Buffer().write(body)).apply(configure)
        )
    }

    /** lane.post on its own thread; the result or error is in the returned future. */
    private fun post(body: ByteArray, channelId: Int = 1): CompletableFuture<ByteArray> {
        val result = CompletableFuture<ByteArray>()
        background("post") {
            try {
                result.complete(lane.post(body, channelId))
            } catch (e: Throwable) {
                result.completeExceptionally(e)
            }
        }
        return result
    }

    private fun <T> CompletableFuture<T>.await(ms: Long = 2000): T = get(ms, TimeUnit.MILLISECONDS)

    private fun <T> CompletableFuture<T>.awaitError(ms: Long = 2000): Throwable = try {
        get(ms, TimeUnit.MILLISECONDS)
        throw AssertionError("expected the request to fail")
    } catch (e: java.util.concurrent.ExecutionException) {
        e.cause!!
    }

    /** Server-side TCP connections that carried requests (the first request of each has sequence 0). */
    private fun serverConnections(): Int = exchanges.count { it.sequence == 0 }

    private fun channel(id: Int = 1): CfH2Channel = CfH2Channel(lane, id, "wire-test")

    @Test
    fun fastResponseDoesNotWaitForUnrelatedLongPolls() {
        val slow1 = post(rep('1', 40))
        val slow2 = post(rep('2', 40))
        val fast = post(rep('3', 40))
        val received = (0 until 3).map { nextRequest() }.associateBy { it.body[0].toInt().toChar() }
        received.getValue('3').respond()
        assertArrayEquals(rep('r', 40), fast.await(500))
        assertFalse(slow1.isDone)
        assertFalse(slow2.isDone)
        received.getValue('1').respond()
        received.getValue('2').respond()
        slow1.await()
        slow2.await()
        assertEquals(1, lane.tcpConnections)
        assertEquals(1, serverConnections())
    }

    @Test
    fun preflightAndPostsUseSameTlsConnection() {
        autoHead = false
        val preflight = CompletableFuture<Unit>()
        background("preflight") {
            try {
                preflight.complete(lane.preflight())
            } catch (e: Throwable) {
                preflight.completeExceptionally(e)
            }
        }
        val head = nextRequest()
        assertEquals("HEAD", head.method)
        head.reply.complete(MockResponse().setResponseCode(501))
        preflight.await()
        val task = post(rep('x', 40))
        val request = nextRequest()
        assertEquals("POST", request.method)
        assertEquals("application/octet-stream", request.request.getHeader("content-type"))
        assertEquals("identity", request.request.getHeader("accept-encoding"))
        assertArrayEquals(rep('x', 40), request.body)
        request.respond()
        task.await()
        assertEquals(1, lane.tcpConnections)
        assertEquals(1, request.sequence)
        assertEquals(1, serverConnections())
    }

    @Test
    fun http1OnlyOriginIsRejectedBeforeAnyRequest() {
        val http1 = startServer(listOf(Protocol.HTTP_1_1)).also { extraServers += it }
        val http1Lane = newLane(http1)
        try {
            val error = assertThrows(IOException::class.java) { http1Lane.preflight() }
            assertTrue(error.message, error.message!!.contains("HTTP/1.1"))
            assertEquals(0, http1.requestCount)
        } finally {
            http1Lane.close()
        }
    }

    @Test
    fun closingAChannelResetsOnlyItsStreams() {
        val closing = channel(1)
        val healthy = channel(2)
        closing.send(rep('a', 40), false)
        closing.send(rep('b', 40), false)
        healthy.send(rep('h', 40), false)
        val received = (0 until 3).map { nextRequest() }.associateBy { it.body[0].toInt().toChar() }
        closing.close()
        assertTrue(closing.closeDone)
        assertTrue(closing.pendingTasks().isEmpty())
        received.getValue('h').respond(rep('g', 40))
        assertArrayEquals(rep('g', 40), healthy.receive(1000))
        val next = channel(3)
        next.send(rep('n', 40), false)
        nextRequest().respond(rep('o', 40))
        assertArrayEquals(rep('o', 40), next.receive(1000))
        assertEquals(1, lane.tcpConnections)
        assertEquals(1, serverConnections())
        assertEquals(0.0, lane.failedUntil, 0.0)
    }

    @Test
    fun largeBodiesCrossFlowControlWindows() {
        // Five 4 MiB replies exceed OkHttp's 16 MiB connection window several times over.
        val upload = Bytes.random(1024 * 1024)
        repeat(5) { index ->
            val task = post(if (index == 0) upload else rep('x', 40))
            val request = nextRequest()
            if (index == 0) assertArrayEquals(upload, request.body)
            val reply = rep(index + 1, CfH2Tuning.MAX_PACKET)
            request.respond(reply)
            assertArrayEquals(reply, task.await(5000))
        }
        assertEquals(1, lane.tcpConnections)
        assertEquals(0L, lane.replyBufferBytes)
    }

    @Test
    fun truncatedBodyClosesChannelWithoutPartialNativeFrame() {
        val tag = MtConst.PROTO_TAG_INTERMEDIATE
        val native = NativeClient(tag)
        val channel = channel()
        val bridge = background("bridge") { bridgeH2(ctx, native.input, native.output, channel, native.crypto, tag, "wire-test") }
        native.send(cat(CfH2Framing.int32le(40), rep('k', 40)))
        nextRequest().respond(rep('p', 20)) { setHeader("content-length", 40) }
        bridge.join(2000)
        assertFalse(bridge.isAlive)
        assertTrue(channel.closed)
        assertEquals(0, native.output.bytes().size)
        assertEquals(1, lane.errors)
        assertTrue(lane.failedUntil > 0)
    }

    @Test
    fun peerResetDuringBodyFailsOnlyThatChannel() {
        val tag = MtConst.PROTO_TAG_INTERMEDIATE
        val native = NativeClient(tag)
        val channel = channel()
        var bridge: Thread? = null
        lateinit var healthy: CompletableFuture<ByteArray>
        val lines = captureLogs {
            bridge = background("bridge") { bridgeH2(ctx, native.input, native.output, channel, native.crypto, tag, "wire-test") }
            native.send(cat(CfH2Framing.int32le(40), rep('k', 40)))
            val request = nextRequest()
            healthy = post(rep('h', 40), 2)
            val good = nextRequest()
            request.reply.complete(
                MockResponse().setHeader("content-length", 40).setBody(object : DuplexResponseBody {
                    override fun onRequest(request: RecordedRequest, http2Stream: Http2Stream) {
                        val sink = http2Stream.getSink().buffer()
                        sink.write(bytesOf("partial-response!!!!"))
                        sink.flush()
                        waitFor(what = "partial body at the client") { lane.lock.withLock { lane.replyBufferBytes } == 20L }
                        http2Stream.close(ErrorCode.INTERNAL_ERROR, null)
                    }
                })
            )
            bridge!!.join(2000)
            assertFalse(bridge!!.isAlive)
            assertTrue(channel.closeDone)
            assertTrue(channel.pendingTasks().isEmpty())
            assertEquals(null, channel.transportError)
            assertEquals("a partial HTTP response must never reach the client", 0, native.output.bytes().size)
            assertEquals(0L, lane.replyBufferBytes)
            good.respond()
            assertArrayEquals(rep('r', 40), healthy.await(1000))
        }
        assertEquals(1, lane.tcpConnections)
        val failures = lines.filter { it.startsWith("WARN") || it.startsWith("ERROR") }
        assertEquals(failures.toString(), 1, failures.size)
        assertTrue(failures[0], failures[0].contains("INTERNAL_ERROR"))
        assertTrue(failures[0], failures[0].contains("down=20"))
    }

    @Test
    fun goawayMakesNextRequestReconnect() {
        val first = post(rep('a', 40))
        nextRequest().respond { socketPolicy = SocketPolicy.DISCONNECT_AT_END }
        assertArrayEquals(rep('r', 40), first.await())
        Thread.sleep(50) // let the GOAWAY arrive
        val second = post(rep('b', 40))
        val request = nextRequest()
        assertEquals(0, request.sequence)
        request.respond()
        assertArrayEquals(rep('r', 40), second.await())
        assertEquals(2, lane.tcpConnections)
    }

    @Test
    fun connectionLossFailsPendingRequestsAndNextRequestReconnects() {
        val pending = listOf(post(rep('a', 40)), post(rep('b', 40)))
        val requestsBefore = (0 until 2).map { nextRequest() }
        val dropping = post(rep('c', 40))
        nextRequest().respond { socketPolicy = SocketPolicy.DISCONNECT_AFTER_REQUEST }
        for (task in pending + dropping) assertTrue(task.awaitError() is IOException)
        for (request in requestsBefore) request.respond()
        val next = post(rep('n', 40))
        val again = nextRequest()
        // Requests that may have reached the server are not resent by OkHttp on the new connection.
        assertArrayEquals(rep('n', 40), again.body)
        again.respond()
        assertArrayEquals(rep('r', 40), next.await())
        assertEquals(2, lane.tcpConnections)
        Thread.sleep(50)
        assertTrue(requests.isEmpty())
    }

    @Test
    fun unreachableFirstAddressFallsBackToTheNext() {
        // 127.0.0.2 is loopback too, but nothing listens there: the connect is refused at once.
        lane.close()
        val twoAddresses = client.newBuilder().dns(object : Dns {
            override fun lookup(hostname: String): List<InetAddress> =
                listOf(InetAddress.getByName("127.0.0.2"), InetAddress.getByName("127.0.0.1"))
        }).build()
        lane = newLane(server, twoAddresses)
        val task = post(rep('x', 40))
        nextRequest().respond()
        assertArrayEquals(rep('r', 40), task.await())
        assertEquals(1, serverConnections())
    }

    @Test
    fun readTimeoutFailsOnlyItsRequestAndKeepsTheConnection() {
        lane.close()
        lane = newLane(server, client.newBuilder().readTimeout(300, TimeUnit.MILLISECONDS).build())
        val stalled = post(rep('s', 40))
        nextRequest() // never answered
        val healthy = post(rep('h', 40))
        nextRequest().respond()
        assertArrayEquals(rep('r', 40), healthy.await())
        assertTrue(stalled.awaitError() is InterruptedIOException)
        // OkHttp checks the connection with a PING after a stream timeout; this server answers.
        Thread.sleep(100)
        val next = post(rep('n', 40))
        nextRequest().respond()
        next.await()
        assertEquals(1, lane.tcpConnections)
    }

    @Test
    fun binaryTransportErrorIsTerminalWithoutDomainCooldown() {
        val channel = channel()
        channel.send(rep('k', 40), false)
        nextRequest().respond(CfH2Framing.int32le(-404))
        channel.awaitPending()
        assertTrue(channel.closed)
        assertEquals(-404, channel.transportError)
        assertEquals(0.0, lane.failedUntil, 0.0)
        assertEquals(0L, lane.replyBufferBytes)
        channel.close()
    }

    @Test
    fun obfuscatedClientsPreservePacketsThroughFullH2Path() {
        // pool.open -> preflight -> channel -> bridgeH2, with real AES-CTR client streams.
        // The CF host kws2.example.org:<port> resolves to this machine (see the client's Dns).
        val pool = CfH2Pool(ctx, CfH2Tuning()) { host -> OkHttpCfH2Transport(host, client) }.also { pools += it }
        pool.balancer = Balancer().apply { updateDomainsList(listOf("example.org:${server.port}")) }
        val opened = ArrayList<CfH2Channel>()
        val bridges = ArrayList<Thread>()
        for (tag in listOf(MtConst.PROTO_TAG_ABRIDGED, MtConst.PROTO_TAG_INTERMEDIATE, MtConst.PROTO_TAG_SECURE)) {
            val label = "tag=${Bytes.toHex(tag)}"
            val peers = ArrayList<NativeClient>()
            val sent = HashMap<Pair<Int, Int>, Exchange>()
            for (index in 0 until 2) {
                val channel = pool.open(2, "peer$index")
                assertNotNull(label, channel)
                opened += channel!!
                val native = NativeClient(tag)
                peers += native
                bridges += background("bridge") {
                    bridgeH2(ctx, native.input, native.output, channel, native.crypto, tag, "peer$index")
                }
                val bodies = listOf(
                    cat(ByteArray(8), Bytes.random(8), CfH2Framing.int32le(20), Bytes.random(20)),
                    cat(bytesOf("samekey!"), Bytes.random(32)),
                    cat(bytesOf("samekey!"), Bytes.random(131112 - 8)),
                    cat(bytesOf("samekey!"), Bytes.random(48)),
                )
                // Extended plaintext padding: MTProtoKit (236 + 15) and Android (256), not just TCP's 15.
                val paddings = listOf(if (index == 0) 251 else 256, 1, 7, 0)
                val wire = native.encrypt(cat(*bodies.indices.map {
                    NativeClient.frame(bodies[it], tag, quick = true, padding = paddings[it])
                }.toTypedArray()))
                var start = 0
                for (end in listOf(13, 57, 65, 78, wire.size)) {
                    native.input.feed(wire.copyOfRange(start, end))
                    start = end
                    Thread.sleep(1)
                }
                val expected = bodies.withIndex().associate { (packet, body) -> Bytes.toHex(body) to packet }.toMutableMap()
                repeat(bodies.size) {
                    val request = nextRequest()
                    val packet = expected.remove(Bytes.toHex(request.body))
                    assertNotNull("$label: HTTP body differs from native input", packet)
                    sent[index to packet!!] = request
                }
            }

            fun checkReply(peer: NativeClient, expected: ByteArray) {
                val body = peer.nextReply()
                assertArrayEquals(label, expected, body.copyOf(expected.size))
                val padding = body.size - expected.size
                assertTrue("$label padding=$padding", if (tag.contentEquals(MtConst.PROTO_TAG_SECURE)) padding in 0..3 else padding == 0)
            }

            for ((index, packet) in listOf(1 to 2, 0 to 2, 0 to 0, 1 to 0, 0 to 1)) {
                val reply = ByteArray(72) { if (it % 2 == 0) (0x30 + index).toByte() else packet.toByte() }
                sent.getValue(index to packet).respond(reply)
                checkReply(peers[index], reply)
            }
            sent.getValue(0 to 3).respond(bytesOf("not found"), status = 404)
            checkReply(peers[0], CfH2Framing.int32le(-404))
            waitFor(what = "peer 0 closed") { peers[0].output.closed }
            sent.getValue(1 to 1).respond(bytesOf("healthy!".repeat(9)))
            checkReply(peers[1], bytesOf("healthy!".repeat(9)))
            sent.getValue(1 to 3).respond(CfH2Framing.int32le(-429))
            checkReply(peers[1], CfH2Framing.int32le(-429))
            waitFor(what = "peer 1 closed") { peers[1].output.closed }
        }
        for (bridge in bridges) bridge.join(2000)
        assertTrue(bridges.none { it.isAlive })
        assertEquals(6, opened.size)
        assertEquals(1, opened.map { it.lane }.toSet().size)
        assertTrue(opened.all { it.closeDone && it.pendingTasks().isEmpty() })
        assertTrue(opened.all { it.quickRequests == 4 })
        val poolLane = opened[0].lane
        assertEquals(1, poolLane.tcpConnections)
        assertEquals(0.0, poolLane.failedUntil, 0.0)
        assertEquals("example.org:${server.port}", pool.balancer.domainsForDc(2).first())
        if (requests.isNotEmpty()) fail("unexpected requests: ${requests.map { it.method }}")
    }

    companion object {
        private val certificate = HeldCertificate.Builder()
            .addSubjectAlternativeName("localhost")
            .addSubjectAlternativeName("kws2.example.org")
            .build()
        private val serverCerts = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        private val clientCerts = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
    }
}
