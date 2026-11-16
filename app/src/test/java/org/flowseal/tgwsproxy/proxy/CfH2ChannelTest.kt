package org.flowseal.tgwsproxy.proxy

import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.concurrent.withLock

/**
 * Channels, replays, capacity rotation and the native bridge on a fake HTTP endpoint
 * (upstream tests/test_cf_h2.py HttpMultiplexTest, which uses httpx.MockTransport).
 */
class CfH2ChannelTest {

    private lateinit var ctx: ProxyContext
    private lateinit var lane: CfH2Lane
    private val channels = ArrayList<CfH2Channel>()
    private var nextId = 0
    private val t get() = lane.t

    private val samekey = bytesOf("samekey!")
    private val tags = listOf(MtConst.PROTO_TAG_ABRIDGED, MtConst.PROTO_TAG_INTERMEDIATE, MtConst.PROTO_TAG_SECURE)

    @Before
    fun setUp() {
        ctx = ProxyContext(ProxySettings(secretHex = "ab".repeat(16)))
        lane = CfH2Lane("kws4.example.org", 1, ctx, CfH2Tuning(), FakeTransport { FakeResponse() })
    }

    @After
    fun tearDown() {
        for (channel in channels) channel.stopRecovery()
        lane.close()
        ctx.shutdown()
        ProxyLog.verbose = false
    }

    private fun channel(): CfH2Channel = CfH2Channel(lane, ++nextId, "owned-test").also { channels += it }

    private fun transport(traceSend: Boolean = true, handler: (FakeRequest) -> FakeResponse): FakeTransport =
        FakeTransport(traceSend, handler).also { lane.transport = it }

    private fun recovery(channel: CfH2Channel): Thread = background("recover") { channel.recover() }

    private fun stop(channel: CfH2Channel, thread: Thread) {
        channel.stopRecovery()
        thread.join(2000)
        assertFalse("recovery did not stop", thread.isAlive)
    }

    /** channel.send that must return within [ms] (upstream: asyncio.wait_for(channel.send(...), ms)). */
    private fun sendWithin(channel: CfH2Channel, body: ByteArray, ms: Long = 1000) {
        var error: Throwable? = null
        val sender = background("send") {
            try {
                channel.send(body, false)
            } catch (e: Throwable) {
                error = e
            }
        }
        sender.join(ms)
        assertFalse("send still waiting after ${ms}ms", sender.isAlive)
        error?.let { throw it }
    }

    /**
     * Sends [bodies] one by one, each only after the previous one is marked sent, so that request
     * ages follow the send order as they do on upstream's single event loop.
     */
    private fun sendInOrder(channel: CfH2Channel, bodies: List<ByteArray>) {
        for ((index, b) in bodies.withIndex()) {
            channel.send(b, false)
            waitFor(what = "request sent") { lane.lock.withLock { channel.sentSince.size } == index + 1 }
        }
    }

    private fun body(fill: Int, prefix: ByteArray = samekey) = cat(prefix, rep(fill, 32))
    private fun body(fill: Char, prefix: ByteArray = samekey) = cat(prefix, rep(fill, 32))
    private fun text(b: ByteArray) = String(b, Charsets.ISO_8859_1)

    private fun bridge(client: NativeClient, channel: CfH2Channel, tag: ByteArray): Thread =
        background("bridge") { bridgeH2(ctx, client.input, client.output, channel, client.crypto, tag, "owned-test") }

    @Test
    fun sameAuthPrefixOutOfOrderRepliesStayWithSourceChannel() {
        val firstStarted = CountDownLatch(1)
        val releaseFirst = CountDownLatch(1)
        val bodyA = body('a')
        val bodyB = body('b')
        transport { req ->
            if (req.content.contentEquals(bodyA)) {
                firstStarted.countDown()
                req.await(releaseFirst)
            }
            FakeResponse(content = req.content)
        }
        val first = channel()
        val second = channel()
        first.send(bodyA, false)
        assertTrue(firstStarted.await(1, TimeUnit.SECONDS))
        second.send(bodyB, false)
        assertArrayEquals(bodyB, second.receive(1000))
        releaseFirst.countDown()
        assertArrayEquals(bodyA, first.receive(1000))
        assertEquals(2, lane.maxInflight)
    }

    @Test
    fun closeOneChannelDoesNotCancelAnother() {
        transport { req -> if (req.content[0] == 'a'.code.toByte()) req.hang() else FakeResponse(content = req.content) }
        val first = channel()
        val second = channel()
        first.send(rep('a', 40), false)
        first.close()
        second.send(rep('b', 40), false)
        assertArrayEquals(rep('b', 40), second.receive(1000))
        second.close()
        assertEquals(0, lane.inflight)
        assertEquals(0L, lane.queuedBytes)
        assertFalse(lane.closed)
    }

    @Test
    fun backpressureWaitsInsteadOfDroppingRequests() {
        val release = CountDownLatch(1)
        transport { req ->
            req.await(release)
            FakeResponse(content = req.content)
        }
        val channel = channel()
        repeat(t.maxChannelRequests) { channel.send(rep('x', 40), false) }
        val extra = background { channel.send(rep('y', 40), false) }
        Thread.sleep(10)
        assertTrue(extra.isAlive)
        assertEquals(t.maxChannelRequests, channel.pendingTasks().size)
        release.countDown()
        extra.join(1000)
        assertFalse(extra.isAlive)
        val received = (0..t.maxChannelRequests).map { channel.receive(1000) }
        assertEquals(1, received.count { it.contentEquals(rep('y', 40)) })
    }

    @Test
    fun httpErrorClosesOnlyItsChannelWithoutReplayingPacket() {
        val fake = transport { FakeResponse(503) }
        val channel = channel()
        channel.send(rep('x', 40), false)
        val error = assertThrows(IOException::class.java) { channel.receive(1000) }
        assertTrue(error.message, error.message!!.contains("503"))
        assertEquals(listOf("x".repeat(40)), fake.callTexts())
        assertTrue(channel.closed)
        assertFalse(lane.closed)
    }

    @Test
    fun transportErrorReachesClientBeforeCloseWithoutCoolingDomain() {
        for (tag in tags) {
            for (status in listOf(403, 404, 429, 444)) {
                val label = "tag=${Bytes.toHex(tag)} status=$status"
                var bodyRead = false
                val fake = transport { req ->
                    if (req.content.contentEquals(rep('h', 40))) {
                        FakeResponse(content = rep('r', 40))
                    } else {
                        FakeResponse(
                            status, headers = mapOf("content-type" to "text/html"),
                            body = StepBody(Runnable { bodyRead = true }, rep('e', 8)),
                        )
                    }
                }
                val channel = channel()
                val client = NativeClient(tag)
                val draining = CountDownLatch(1)
                val release = CountDownLatch(1)
                client.output.onFlush = {
                    draining.countDown()
                    release.await(2, TimeUnit.SECONDS)
                }
                val packet = rep('k', 40)
                client.send(CfH2Framing.encodeReply(packet, tag))
                val task = bridge(client, channel, tag)
                val healthy: CfH2Channel
                try {
                    assertTrue(label, draining.await(1, TimeUnit.SECONDS))
                    assertTrue(label, task.isAlive)
                    assertFalse(label, channel.closeDone)
                    val output = client.output.bytes()
                    if (tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED)) {
                        assertArrayEquals(label, cat(byteArrayOf(1), CfH2Framing.int32le(-status)), output)
                    } else {
                        val length = Bytes.u32le(output, 0).toInt()
                        assertEquals(label, output.size - 4, length)
                        assertArrayEquals(label, CfH2Framing.int32le(-status), output.copyOfRange(4, 8))
                        assertTrue(label, length <= 7)
                    }
                    assertEquals(label, 0.0, lane.failedUntil, 0.0)
                    healthy = channel()
                    healthy.send(rep('h', 40), false)
                    assertArrayEquals(label, rep('r', 40), healthy.receive(1000))
                    assertEquals(label, listOf(text(packet), "h".repeat(40)), fake.callTexts())
                    assertFalse(label, lane.closed)
                } finally {
                    release.countDown()
                    task.join(2000)
                }
                assertFalse(label, task.isAlive)
                assertTrue(label, channel.closeDone)
                assertTrue(label, channel.pendingTasks().isEmpty())
                assertFalse(label, bodyRead)
                healthy.close()
            }
        }
    }

    @Test
    fun longPollsCannotBlockFreshRequestAndRetiredPacketRecovers() {
        val bodies = (0 until t.maxChannelRequests).map { body(it) }
        val fresh = body('n')
        val calls = CopyOnWriteArrayList<String>()
        transport { req ->
            calls.add(req.text)
            when {
                req.content.contentEquals(fresh) -> FakeResponse(content = rep('n', 40))
                req.content.contentEquals(bodies[0]) && calls.count { it == text(bodies[0]) } == 2 ->
                    FakeResponse(content = rep('r', 40))
                else -> req.hang()
            }
        }
        val channel = channel()
        sendInOrder(channel, bodies)
        val original = channel.pendingTasks().first()
        t.replayRequestSeconds = 0.02
        t.replayIdleSeconds = 0.01
        t.replayCheckSeconds = 0.005
        val recovery = recovery(channel)
        try {
            sendWithin(channel, fresh)
            val received = (0 until 2).map { text(channel.receive(1000)) }
            assertEquals(setOf("n".repeat(40), "r".repeat(40)), received.toSet())
            waitFor(what = "rotated original") { original.done }
            assertTrue(original.cancelled)
            assertTrue(lane.lock.withLock { channel.replayHistory[0].retired })
            assertEquals(2, calls.count { it == text(bodies[0]) })
            assertEquals(1, channel.capacityRotations)
            assertEquals(t.maxChannelRequests, lane.maxInflight)
            assertEquals(0, lane.errors)
            assertFalse(channel.closed)
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun sharedLaneLongPollsCannotBlockNewChannel() {
        val fresh = body('n')
        transport { req ->
            if (req.content.contentEquals(fresh)) FakeResponse(content = rep('n', 40)) else req.hang()
        }
        val first = channel()
        val second = channel()
        val waiting = channel()
        t.maxLaneRequests = 2
        t.replayRequestSeconds = 0.02
        t.replayCheckSeconds = 0.005
        first.send(body('a'), false)
        second.send(body('b'), false)
        val originals = listOf(first, second).map { it.pendingTasks().first() }
        val recovery = recovery(waiting)
        try {
            sendWithin(waiting, fresh)
            assertArrayEquals(rep('n', 40), waiting.receive(1000))
            waitFor(what = "capacity rotation") { lane.lock.withLock { lane.capacityRotations } == 1 }
            assertEquals(1, originals.count { it.cancelled && it.done })
            assertEquals(1, first.capacityRotations + second.capacityRotations)
            assertEquals(1, lane.capacityRotations)
            assertEquals(2, lane.maxInflight)
        } finally {
            stop(waiting, recovery)
        }
    }

    @Test
    fun uploadRoomAccountsForWaitingPacketSize() {
        for (laneLimit in listOf(false, true)) {
            val started = CountDownLatch(1)
            transport { req ->
                if (req.content.contentEquals(rep('k', 40))) {
                    started.countDown()
                    req.hang()
                }
                FakeResponse(content = rep('n', 40))
            }
            val channel = channel()
            if (laneLimit) t.maxLaneBytes = 60 else t.maxChannelBytes = 60
            t.replayRequestSeconds = 0.02
            t.replayCheckSeconds = 0.005
            channel.send(rep('k', 40), false)
            assertTrue(started.await(1, TimeUnit.SECONDS))
            val recovery = recovery(channel)
            try {
                // 20 bytes are free, but the pending upload needs 40.
                sendWithin(channel, rep('n', 40), 500)
                assertArrayEquals(rep('n', 40), channel.receive(500))
                waitFor(what = "capacity rotation") { lane.lock.withLock { channel.capacityRotations } == 1 }
            } finally {
                stop(channel, recovery)
                channel.close()
                lane.t.maxLaneBytes = CfH2Tuning().maxLaneBytes
                lane.t.maxChannelBytes = CfH2Tuning().maxChannelBytes
            }
        }
    }

    @Test
    fun closeReleasesRequestCancelledBeforeItStartsOnce() {
        var reached = false
        transport {
            reached = true
            FakeResponse()
        }
        val held = LinkedBlockingQueue<Runnable>()
        lane.executor = Executor { held.put(it) }
        t.cancelWaitMillis = 50
        val channel = channel()
        channel.send(rep('k', 40), false)
        val packet = lane.lock.withLock { channel.replayHistory[0] }
        channel.close()
        channel.close()
        fun assertReleased() = lane.lock.withLock {
            assertEquals(0, lane.inflight)
            assertEquals(0L, lane.queuedBytes)
            assertEquals(0L, channel.pendingBytes)
            assertTrue(channel.pending.isEmpty())
            assertTrue(channel.pendingSince.isEmpty())
            assertTrue(channel.sentSince.isEmpty())
            assertTrue(packet.originals.isEmpty())
        }
        assertReleased()
        // The request thread starts only now: it must neither reach HTTP nor release twice.
        assertEquals(1, held.size)
        held.poll()!!.run()
        assertReleased()
        assertFalse(reached)
    }

    @Test
    fun capacityRotationKeepsUploadAndStartedResponseIntact() {
        val uploading = body(0)
        val receiving = body(1)
        val waiting = body(2)
        val fresh = body('n')
        val bodyStarted = CountDownLatch(1)
        transport(traceSend = false) { req ->
            when {
                req.content.contentEquals(uploading) -> req.hang() // body never finishes sending
                req.content.contentEquals(receiving) -> {
                    req.sent()
                    FakeResponse(body = StepBody(rep('r', 20), Runnable { bodyStarted.countDown() }, StepBody.HANG))
                }
                req.content.contentEquals(waiting) -> {
                    req.sent()
                    req.hang()
                }
                else -> {
                    req.sent()
                    FakeResponse(content = rep('n', 40))
                }
            }
        }
        val channel = channel()
        t.maxChannelRequests = 3
        t.replayRequestSeconds = 0.02
        t.replayCheckSeconds = 0.005
        for (b in listOf(uploading, receiving, waiting)) channel.send(b, false)
        assertTrue(bodyStarted.await(1, TimeUnit.SECONDS))
        val tasks = channel.pendingTasks()
        val recovery = recovery(channel)
        try {
            sendWithin(channel, fresh)
            assertArrayEquals(rep('n', 40), channel.receive(1000))
            waitFor(what = "rotated request") { tasks[2].done }
            assertFalse(tasks[0].done)
            assertFalse(tasks[1].done)
            assertTrue(tasks[2].cancelled)
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun capacityRotationNeverRetiresUnretainedOrPlaintextRequest() {
        val release = CountDownLatch(1)
        transport { req ->
            req.await(release)
            FakeResponse(content = rep('r', 40))
        }
        val channel = channel()
        t.maxChannelRequests = 2
        t.replayRequestSeconds = 0.005
        t.replayCheckSeconds = 0.002
        channel.send(cat(ByteArray(8), rep('p', 32)), false)
        channel.send(cat(samekey, rep('u', 64 * 1024)), false)
        val extra = background { channel.send(body('n'), false) }
        val recovery = recovery(channel)
        try {
            Thread.sleep(40)
            assertTrue(extra.isAlive)
            assertEquals(0, channel.capacityRotations)
            assertTrue(channel.pendingTasks().none { it.done })
            release.countDown()
            extra.join(1000)
            assertFalse(extra.isAlive)
        } finally {
            release.countDown()
            stop(channel, recovery)
        }
    }

    @Test
    fun http1RejectedByPreflight() {
        transport { FakeResponse(protocol = "HTTP/1.1") }
        val error = assertThrows(CfH2ValueError::class.java) { lane.preflight() }
        assertTrue(error.message, error.message!!.contains("HTTP/1.1"))
    }

    @Test
    fun telegramHead501StillAllowsHttp2Preflight() {
        transport { FakeResponse(501) }
        lane.preflight()
    }

    @Test
    fun missingHttpEndpointIsRejectedBeforeNativeRequests() {
        transport { FakeResponse(404) }
        val error = assertThrows(CfH2ConnectionError::class.java) { lane.preflight() }
        assertTrue(error.message, error.message!!.contains("preflight HTTP 404"))
    }

    private fun packetBridge(contentLength: Boolean = true, truncate: Boolean = false, concurrentSmall: Boolean = false) {
        val firstChunkRead = CountDownLatch(1)
        val releaseTail = CountDownLatch(1)
        val body = rep('x', 64 * 1024 + 40)
        val firstChunk = body.copyOf(16384)
        val tail = body.copyOfRange(16384, body.size)
        transport { req ->
            if (req.content.contentEquals(rep('s', 40))) {
                FakeResponse(content = rep('z', 40))
            } else {
                val steps = mutableListOf<Any>(firstChunk, Runnable { firstChunkRead.countDown() }, releaseTail)
                if (!truncate) steps.add(tail)
                val headers = if (contentLength) mapOf("content-length" to body.size.toString()) else emptyMap()
                FakeResponse(headers = headers, body = StepBody(*steps.toTypedArray()))
            }
        }
        val tag = MtConst.PROTO_TAG_INTERMEDIATE
        val client = NativeClient(tag)
        val channel = channel()
        val task = bridge(client, channel, tag)
        client.send(cat(CfH2Framing.int32le(40), rep('l', 40)))
        try {
            assertTrue(firstChunkRead.await(1, TimeUnit.SECONDS))
            assertEquals(0, client.output.bytes().size)
            val small = cat(CfH2Framing.int32le(40), rep('z', 40))
            if (concurrentSmall) {
                client.send(cat(CfH2Framing.int32le(40), rep('s', 40)))
                assertArrayEquals(small, client.output.awaitSize(small.size, 1000))
            }
            releaseTail.countDown()
            if (truncate) {
                task.join(1000)
                assertFalse(task.isAlive)
                assertTrue(channel.closed)
                assertEquals(0, client.output.bytes().size)
            } else {
                var expected = cat(CfH2Framing.int32le(body.size), body)
                if (concurrentSmall) expected = cat(small, expected)
                val output = client.output.awaitSize(expected.size, 1000)
                assertTrue(output.size >= expected.size)
                assertArrayEquals(expected, output.copyOf(expected.size))
            }
        } finally {
            releaseTail.countDown()
            client.input.finish()
            task.join(2000)
        }
    }

    @Test
    fun nativeFrameStartsOnlyAfterEntireBodyIsAvailable() = packetBridge()

    @Test
    fun readyReplyBypassesIncompleteLargeResponseOnSameChannel() = packetBridge(concurrentSmall = true)

    @Test
    fun responseWithoutLengthUsesBufferedFraming() = packetBridge(contentLength = false)

    @Test
    fun truncatedStreamClosesNativeChannel() = packetBridge(truncate = true)

    @Test
    fun recoveryPausesDuringBodyReceiveAndResumesAfterwards() {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = CopyOnWriteArrayList<String>()
        transport { req ->
            calls.add(req.text)
            if (calls.size == 1) {
                FakeResponse(body = StepBody(rep('r', 20), Runnable { started.countDown() }, release, rep('r', 20)))
            } else {
                FakeResponse(content = rep('s', 40))
            }
        }
        val channel = channel()
        channel.send(rep('x', 40), false)
        assertTrue(started.await(1, TimeUnit.SECONDS))
        t.replayIdleSeconds = 0.01
        t.replayCheckSeconds = 0.005
        val recovery = recovery(channel)
        try {
            Thread.sleep(60)
            assertEquals(1, calls.size)
            assertEquals(1, channel.receivingHttp)
            release.countDown()
            assertArrayEquals(rep('r', 40), channel.receive(1000))
            assertArrayEquals(rep('s', 40), channel.receive(1000))
            assertEquals(listOf("x".repeat(40), "x".repeat(40)), calls)
            assertEquals(0, channel.receivingHttp)
            assertEquals(0L, lane.replyBufferBytes)
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun laneReplyMemoryBoundAndCancellationCleanup() {
        val started = CountDownLatch(1)
        transport { req ->
            if (req.content.contentEquals(rep('a', 40))) {
                FakeResponse(body = StepBody(rep('r', 32), Runnable { started.countDown() }, StepBody.HANG))
            } else {
                FakeResponse(content = rep('r', 16))
            }
        }
        val slow = channel()
        t.maxLaneReplyBytes = 40
        slow.send(rep('a', 40), false)
        assertTrue(started.await(1, TimeUnit.SECONDS))
        assertEquals(32L, lane.replyBufferBytes)
        val error = assertThrows(CfH2ReplyBufferFull::class.java) { lane.post(rep('b', 40), 2) }
        assertTrue(error.message!!.contains("response buffers"))
        assertEquals(32L, lane.replyBufferBytes)
        assertEquals(0.0, lane.failedUntil, 0.0)
        slow.close()
        assertEquals(0, slow.receivingHttp)
        assertEquals(0L, lane.replyBufferBytes)
        assertArrayEquals(rep('r', 16), lane.post(rep('b', 40), 2))
    }

    @Test
    fun nativeDisconnectDoesNotCoolDownHealthyLane() {
        transport { FakeResponse(content = rep('r', 65536)) }
        val tag = MtConst.PROTO_TAG_INTERMEDIATE
        val client = NativeClient(tag)
        client.output.onFlush = { throw IOException("Connection lost") }
        val channel = channel()
        client.send(cat(CfH2Framing.int32le(40), rep('x', 40)))
        val task = bridge(client, channel, tag)
        task.join(1000)
        assertFalse(task.isAlive)
        assertTrue(channel.closed)
        assertEquals(0.0, lane.failedUntil, 0.0)
        assertEquals(0, lane.errors)
        val healthy = channel()
        healthy.send(rep('h', 40), false)
        assertArrayEquals(rep('r', 65536), healthy.receive(1000))
    }

    @Test
    fun recoveryStopIsNotLostWhenWakeupArrivesAtTheSameTime() {
        val channel = channel()
        t.replayCheckSeconds = 10.0
        val recovery = recovery(channel)
        lane.lock.withLock { channel.wakeReceiver() }
        channel.stopRecovery()
        recovery.join(200)
        assertFalse(recovery.isAlive)
    }

    @Test
    fun slowReceiverQueueOverflowDoesNotBreakOtherChannels() {
        transport { req -> FakeResponse(content = req.content) }
        val slow = channel()
        val healthy = channel()
        t.maxChannelBytes = 80
        repeat(3) {
            slow.send(rep('s', 40), false)
            slow.awaitPending()
        }
        assertThrows(CfH2BufferError::class.java) { slow.receive(1000) }
        healthy.send(rep('h', 40), false)
        assertArrayEquals(rep('h', 40), healthy.receive(1000))
        assertFalse(lane.closed)
    }

    private fun pool(tuning: CfH2Tuning = CfH2Tuning(), factory: (String) -> CfH2Transport): CfH2Pool =
        CfH2Pool(ctx, tuning, factory).apply { balancer = Balancer().apply { updateDomainsList(listOf("example.org")) } }

    @Test
    fun simultaneousPoolOpensPreflightOnceAndShareLane() {
        val heads = AtomicInteger()
        val hosts = CopyOnWriteArrayList<String>()
        val pool = pool { host ->
            hosts.add(host)
            FakeTransport { req ->
                if (req.method == "HEAD") {
                    heads.incrementAndGet()
                    Thread.sleep(20)
                    FakeResponse(501)
                } else {
                    FakeResponse()
                }
            }
        }
        try {
            val start = CountDownLatch(1)
            val opened = CopyOnWriteArrayList<CfH2Channel?>()
            val openers = (0 until 6).map {
                background("open") {
                    start.await()
                    opened.add(pool.open(4, "owned-test"))
                }
            }
            start.countDown()
            for (opener in openers) opener.join(2000)
            assertEquals(1, heads.get())
            assertEquals(listOf("kws4.example.org"), hosts)
            assertEquals(6, opened.size)
            assertTrue(opened.all { it != null })
            assertEquals(1, opened.map { it!!.lane }.toSet().size)
            assertEquals(6, opened.map { it!!.channelId }.toSet().size)
        } finally {
            pool.close()
        }
    }

    @Test
    fun recoveryReusesExactCiphertextWhenOriginalHttpIsStillPending() {
        val calls = CopyOnWriteArrayList<String>()
        val originalWaiting = CountDownLatch(1)
        val body = cat(bytesOf("opaque-key-and-message-id"), rep('x', 16))
        transport { req ->
            calls.add(req.text)
            if (calls.size == 1) {
                originalWaiting.countDown()
                req.hang()
            }
            FakeResponse(content = rep('r', 40))
        }
        val channel = channel()
        channel.send(body, false)
        assertTrue(originalWaiting.await(1, TimeUnit.SECONDS))
        t.replayRequestSeconds = 0.01
        t.replayCheckSeconds = 0.005
        val recovery = recovery(channel)
        try {
            assertArrayEquals(rep('r', 40), channel.receive(1000))
            assertEquals(listOf(text(body), text(body)), calls)
            assertEquals(1, channel.replayRequests)
            assertEquals(2, lane.maxInflight)
        } finally {
            stop(channel, recovery)
            channel.close()
        }
        assertTrue(channel.pendingTasks().isEmpty())
        assertEquals(0, lane.inflight)
    }

    @Test
    fun recoveryAfterHttpFinishedWithoutNativeReply() {
        val calls = CopyOnWriteArrayList<String>()
        transport { req ->
            calls.add(req.text)
            FakeResponse(content = if (calls.size == 1) ByteArray(0) else rep('r', 40))
        }
        val channel = channel()
        val body = rep('k', 40)
        channel.send(body, false)
        channel.awaitPending()
        assertTrue(lane.lock.withLock { channel.queue.isEmpty() })
        t.replayIdleSeconds = 0.01
        t.replayCheckSeconds = 0.005
        val recovery = recovery(channel)
        try {
            assertArrayEquals(rep('r', 40), channel.receive(1000))
            Thread.sleep(30)
            assertEquals(listOf(text(body), text(body)), calls)
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun idleReceiverPreservesCapacityForNewNativeRequest() {
        val calls = CopyOnWriteArrayList<String>()
        val probesWaiting = CountDownLatch(1)
        transport { req ->
            calls.add(req.text)
            if (calls.count { it == req.text } > 1) {
                if (calls.size == 4) probesWaiting.countDown()
                req.hang()
            }
            FakeResponse(content = rep('r', 40))
        }
        val channel = channel()
        val bodies = (0 until 4).map { body(it) }
        for (b in bodies.take(3)) {
            channel.send(b, false)
            channel.awaitPending()
            channel.receive(1000)
        }
        t.replayIdleSeconds = 0.01
        t.replayCheckSeconds = 0.005
        val recovery = recovery(channel)
        try {
            assertTrue(probesWaiting.await(1, TimeUnit.SECONDS))
            Thread.sleep(30)
            assertEquals(1, channel.replayRequests)
            assertEquals(1, lane.lock.withLock { channel.replayPending.size })
            sendWithin(channel, bodies[3])
            assertArrayEquals(rep('r', 40), channel.receive(1000))
            assertEquals(listOf(text(bodies[2])), calls.subList(3, 4))
        } finally {
            stop(channel, recovery)
            val closers = (0 until 2).map { background("close") { channel.close() } }
            for (closer in closers) closer.join(2000)
        }
        assertEquals(0, lane.inflight)
        assertEquals(0L, channel.pendingBytes)
        assertTrue(channel.replayPending.isEmpty())
    }

    @Test
    fun handshakeAndExpiredCiphertextAreNeverReplayed() {
        val fake = transport { FakeResponse(content = rep('r', 40)) }
        val channel = channel()
        for (b in listOf(cat(ByteArray(8), rep('h', 32)), rep('k', 40))) {
            channel.send(b, false)
            channel.awaitPending()
            channel.receive(1000)
        }
        lane.lock.withLock { channel.replayHistory.last().sentAt -= 1 }
        t.replayIdleSeconds = 0.01
        t.replayCheckSeconds = 0.005
        t.replayMaxAge = 0.0
        val recovery = recovery(channel)
        try {
            Thread.sleep(40)
            assertEquals(2, fake.calls.size)
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun unhelpfulRepliesDoNotCauseUnboundedRecovery() {
        val calls = CopyOnWriteArrayList<Pair<String, Double>>()
        val retriesFinished = CountDownLatch(1)
        transport { req ->
            calls.add(req.text to CfH2Clock.now())
            if (calls.size == 5) retriesFinished.countDown()
            FakeResponse()
        }
        val channel = channel()
        val bodies = (0 until 2).map { body(it) }
        for (b in bodies) channel.send(b, false)
        channel.awaitPending()
        t.replayIdleSeconds = 0.005
        t.replayCheckSeconds = 0.002
        t.replayRetrySeconds = 0.03
        val recovery = recovery(channel)
        try {
            assertTrue(retriesFinished.await(1, TimeUnit.SECONDS))
            Thread.sleep(90)
            val older = calls.filter { it.first == text(bodies[0]) }.map { it.second }
            val latest = calls.filter { it.first == text(bodies[1]) }.map { it.second }
            // Completed history is not scanned; only the latest is polled, with backoff.
            assertEquals(1, older.size)
            assertEquals(4, latest.size)
            for (i in 2 until latest.size) assertTrue(latest[i] - latest[i - 1] >= 0.02)
            assertTrue(channel.pendingTasks().isEmpty())
            assertTrue(channel.replayPending.isEmpty())
            assertEquals(0, lane.inflight)
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun newRepliesRefreshIdleReceiverBudgetWithoutNativeUpload() {
        val replies = (0 until 6).map { body(it) }
        val calls = CopyOnWriteArrayList<String>()
        val count = AtomicInteger()
        val exhausted = CountDownLatch(1)
        transport { req ->
            calls.add(req.text)
            val n = count.incrementAndGet()
            if (n == replies.size + 3) exhausted.countDown()
            FakeResponse(content = if (n <= replies.size) replies[n - 1] else ByteArray(0))
        }
        val channel = channel()
        val body = body('a')
        t.replayIdleSeconds = 0.005
        t.replayCheckSeconds = 0.002
        t.replayRetrySeconds = 0.01
        channel.send(body, false)
        val recovery = recovery(channel)
        try {
            // The client waits for a batch of replies and sends nothing between them. Three
            // successful polls must not use up the budget while more responses arrive.
            for (reply in replies) assertArrayEquals(reply, channel.receive(1000))
            assertTrue(exhausted.await(1, TimeUnit.SECONDS))
            Thread.sleep(50)
            assertEquals(List(replies.size + 3) { text(body) }, calls)
            assertTrue(channel.pendingTasks().isEmpty())
            assertTrue(channel.replayPending.isEmpty())
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun duplicateReplyDoesNotRefreshIdleReceiverBudget() {
        val fake = transport { FakeResponse(content = rep('r', 40)) }
        val channel = channel()
        t.replayIdleSeconds = 0.005
        t.replayCheckSeconds = 0.002
        t.replayRetrySeconds = 0.01
        channel.send(body('a'), false)
        val recovery = recovery(channel)
        try {
            repeat(4) { assertArrayEquals(rep('r', 40), channel.receive(1000)) }
            Thread.sleep(50)
            assertEquals(4, fake.calls.size)
            assertTrue(channel.pendingTasks().isEmpty())
            assertTrue(channel.replayPending.isEmpty())
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun oldPendingRequestHasBoundedRetriesAfterNewerRequests() {
        val body = body('t')
        val originalStarted = CountDownLatch(1)
        val retriesFinished = CountDownLatch(1)
        val attempts = AtomicInteger()
        transport { req ->
            if (req.content.contentEquals(body)) {
                val n = attempts.incrementAndGet()
                if (n == 1) {
                    originalStarted.countDown()
                    req.hang()
                }
                if (n == 4) retriesFinished.countDown()
            }
            FakeResponse()
        }
        val channel = channel()
        channel.send(body, false)
        assertTrue(originalStarted.await(1, TimeUnit.SECONDS))
        val original = channel.pendingTasks().first()
        channel.send(body('n'), false)
        t.replayIdleSeconds = 0.01
        t.replayRequestSeconds = 0.02
        t.replayCheckSeconds = 0.005
        t.replayRetrySeconds = 0.02
        val recovery = recovery(channel)
        try {
            assertTrue(retriesFinished.await(1, TimeUnit.SECONDS))
            Thread.sleep(60)
            assertEquals(4, attempts.get())
            assertFalse(original.done)
            assertTrue(lane.lock.withLock { channel.replayPending.isEmpty() })
        } finally {
            stop(channel, recovery)
        }
    }

    @Test
    fun closedPoolCannotOpenNewChannels() {
        val pool = pool { FakeTransport { FakeResponse(501) } }
        pool.close()
        val error = assertThrows(IOException::class.java) { pool.open(4, "owned-test") }
        assertTrue(error.message!!.contains("pool closed"))
    }

    @Test
    fun concurrentUploadsCannotExceedChannelRequestBound() {
        val release = CountDownLatch(1)
        transport { req ->
            req.await(release)
            FakeResponse(content = req.content)
        }
        val channel = channel()
        repeat(t.maxChannelRequests - 1) { channel.send(rep('k', 40), false) }
        val first = background { channel.send(rep('a', 40), false) }
        val second = background { channel.send(rep('b', 40), false) }
        try {
            waitFor(1000, "one upload") { !first.isAlive || !second.isAlive }
            Thread.sleep(20)
            assertEquals(t.maxChannelRequests, channel.pendingTasks().size)
            assertTrue(first.isAlive != second.isAlive)
            release.countDown()
            first.join(1000)
            second.join(1000)
            assertFalse(first.isAlive || second.isAlive)
        } finally {
            release.countDown()
        }
    }

    @Test
    fun failingPreflightReturnsToWsWithoutConsumingNativeData() {
        val pool = pool {
            FakeTransport { req ->
                if (req.method == "HEAD") throw IOException("owned connection failure")
                FakeResponse()
            }
        }
        try {
            assertNull(pool.open(4, "owned-test"))
            assertTrue(pool.lanes.isEmpty())
        } finally {
            pool.close()
        }
    }

    @Test
    fun hangingSetupReturnsToWsAndCleansUpLane() {
        val transports = CopyOnWriteArrayList<FakeTransport>()
        val pool = pool(CfH2Tuning(setupTimeout = 0.02)) {
            FakeTransport { req -> req.hang() }.also { transports.add(it) }
        }
        try {
            assertNull(pool.open(4, "owned-test"))
            assertNull(pool.open(4, "owned-test"))
            assertEquals(1, transports.size)
            assertTrue(transports[0].closed)
            assertTrue(pool.lanes.isEmpty())
        } finally {
            pool.close()
        }
    }

    @Test
    fun poolRoutesOnlyKnownDcsAndRecordsTheWorkingDomain() {
        val hosts = CopyOnWriteArrayList<String>()
        val pool = CfH2Pool(ctx, CfH2Tuning()) { host ->
            hosts.add(host)
            FakeTransport { req ->
                if (req.method == "HEAD" && host.endsWith("bad.example")) throw IOException("refused")
                FakeResponse(501)
            }
        }
        pool.balancer = Balancer().apply { updateDomainsList(listOf("bad.example", "good.example")) }
        try {
            assertNull(pool.open(10, "owned-test"))
            assertTrue(hosts.isEmpty())
            val channel = pool.open(2, "owned-test")
            assertNotNull(channel)
            assertEquals("kws2.good.example", channel!!.lane.host)
            assertEquals("good.example", pool.balancer.domainsForDc(2).first())
            // The failed domain is cooling down: the next open goes straight to the good one.
            hosts.clear()
            assertNotNull(pool.open(2, "owned-test"))
            assertTrue(hosts.isEmpty())
        } finally {
            pool.close()
        }
        assertTrue(pool.closed)
    }

    @Test
    fun recoveryDoesNotWaitForChannelOrLaneCapacity() {
        val channel = channel()
        val body = rep('k', 40)
        val packet = CfH2ReplayPacket(0.0, body, 0)
        lane.lock.withLock { channel.replayHistory.add(packet) }
        t.maxChannelRequests = 0
        val started = System.nanoTime()
        assertFalse(channel.send(body, false, replay = true))
        t.maxChannelRequests = 8
        t.maxLaneRequests = 0
        assertFalse(channel.send(body, false, replay = true))
        assertTrue(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(100))
        assertFalse(channel.sendLock.isLocked)
        assertFalse(packet.replayed)
        assertEquals(0, channel.requests)
        assertEquals(0, lane.inflight)
    }

    @Test
    fun recoveryDoesNotQueueBehindNativeUpload() {
        val channel = channel()
        val locked = CountDownLatch(1)
        val release = CountDownLatch(1)
        val holder = background {
            channel.sendLock.lock()
            try {
                locked.countDown()
                release.await()
            } finally {
                channel.sendLock.unlock()
            }
        }
        assertTrue(locked.await(1, TimeUnit.SECONDS))
        assertFalse(channel.send(rep('k', 40), false, replay = true))
        release.countDown()
        holder.join(1000)
        assertEquals(0, channel.requests)
    }

    @Test
    fun waitDiagnosticsCombineChannelsAndAreRateLimited() {
        transport { req -> req.hang() }
        val now = CfH2Clock.now()
        repeat(2) {
            val channel = channel()
            channel.send(rep('k', 40), false)
            lane.lock.withLock {
                channel.lastProgress = now - 4
                for (task in channel.pending.keys) channel.pendingSince[task] = now - 4
            }
        }
        val lines = captureLogs { repeat(20) { lane.logWait(now) } }
        assertEquals(lines.toString(), 1, lines.size)
        for (part in listOf("H2 WAIT", "affected=2", "channel=1", "channel=2", "recovery_left=")) {
            assertTrue(lines[0], lines[0].contains(part))
        }
    }

    @Test
    fun newRequestAfterIdleDoesNotLogAStall() {
        transport { req -> req.hang() }
        val channel = channel()
        channel.send(rep('k', 40), false)
        val now = CfH2Clock.now()
        lane.lock.withLock { channel.lastProgress = now - 20 }
        assertEquals(emptyList<String>(), captureLogs { lane.logWait(now) })
    }

    @Test
    fun waitDiagnosticsIncludeOldRequestWhileOtherRepliesProgress() {
        transport { req -> req.hang() }
        val channel = channel()
        channel.send(rep('k', 40), false)
        val now = CfH2Clock.now()
        lane.lock.withLock {
            for (task in channel.pending.keys) channel.pendingSince[task] = now - 4
            channel.lastProgress = now
        }
        val lines = captureLogs { lane.logWait(now) }
        assertEquals(lines.toString(), 1, lines.size)
        assertTrue(lines[0], lines[0].contains("waiting_headers=1"))
        assertTrue(lines[0], lines[0].contains("idle_ms=0"))
    }

    @Test
    fun slowResponseDiagnosticsAreRateLimited() {
        transport { FakeResponse(content = rep('r', 40)) }
        t.slowResponseSeconds = 0.0
        val lines = captureLogs { repeat(10) { lane.post(rep('k', 40), 1) } }
        assertEquals(lines.toString(), 1, lines.size)
        for (part in listOf("H2 SLOW", "headers_ms=", "body_ms=")) assertTrue(lines[0], lines[0].contains(part))
    }

    @Test
    fun pendingDetailsLinkReplayToOriginalAndBoundHistory() {
        val calls = AtomicInteger()
        val originalWaiting = CountDownLatch(1)
        transport { req ->
            if (calls.incrementAndGet() == 1) {
                originalWaiting.countDown()
                req.hang()
            }
            FakeResponse()
        }
        val channel = channel()
        val lines = captureLogs {
            val body = body('p')
            channel.send(body, false)
            assertTrue(originalWaiting.await(1, TimeUnit.SECONDS))
            val original = channel.pendingTasks().first()
            t.replayRequestSeconds = 0.0
            assertTrue(channel.send(body, false, replay = true))
            t.replayRequestSeconds = 3.0
            channel.awaitPending(except = original)
            val (trace, replay) = lane.lock.withLock { channel.requestTraces[original]!! to channel.recentTraces.last() }
            assertEquals(trace.packet, replay.packet)
            assertNotEquals(trace.request, replay.request)
            assertTrue(replay.replay)
            val now = CfH2Clock.now()
            lane.lock.withLock {
                trace.started = now - 4
                channel.pendingSince[original] = now - 4
            }
            lane.logWait(now)
            for (index in 0 until 24) {
                channel.send(body(index), false)
                channel.awaitPending(except = original)
            }
            lane.lock.withLock {
                assertEquals(16, channel.recentTraces.size)
                assertEquals(1, channel.requestTraces.size)
            }
        }
        val output = lines.joinToString("\n")
        for (part in listOf("H2 DETAIL", "pkt=1", "replay=1 phase=complete")) assertTrue(output, output.contains(part))
        assertFalse(output.contains("samekey!"))
    }
}
