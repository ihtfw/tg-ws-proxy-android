package org.flowseal.tgwsproxy.proxy

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException
import java.io.OutputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.concurrent.withLock

/** A request as the fake HTTP endpoint sees it (upstream tests: httpx.Request of a MockTransport). */
internal class FakeRequest(val method: String, val content: ByteArray, val call: FakeCall) {
    val text: String get() = String(content, Charsets.ISO_8859_1)

    /** Tells the lane the body was sent (the upstream tests' trace 'http2.send_request_body.complete'). */
    fun sent() = call.events?.requestBodyEnd()

    /** Never answers; returns only by the call being cancelled (upstream: await asyncio.Event().wait()). */
    fun hang(): Nothing {
        call.awaitOrCancel(null)
        throw AssertionError("unreachable")
    }

    /** Waits for [latch], or fails like a cancelled HTTP call. */
    fun await(latch: CountDownLatch) = call.awaitOrCancel(latch)
}

internal class FakeResponse(
    val status: Int = 200,
    val content: ByteArray = ByteArray(0),
    val protocol: String = "HTTP/2",
    val headers: Map<String, String> = emptyMap(),
    val body: StepBody? = null,
)

/**
 * A response body read step by step: ByteArray steps are data, a CountDownLatch is waited for,
 * a Runnable is run, [HANG] blocks until the call is cancelled. Cancellation fails the read.
 */
internal class StepBody(private vararg val steps: Any) {
    fun open(call: FakeCall): InputStream = object : InputStream() {
        private var index = 0
        private var current: ByteArray? = null
        private var pos = 0

        override fun read(): Int {
            val one = ByteArray(1)
            return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            while (true) {
                call.checkCancelled()
                val cur = current
                if (cur != null && pos < cur.size) {
                    val n = minOf(len, cur.size - pos)
                    System.arraycopy(cur, pos, b, off, n)
                    pos += n
                    return n
                }
                if (index >= steps.size) return -1
                when (val step = steps[index++]) {
                    is ByteArray -> {
                        current = step
                        pos = 0
                    }
                    is CountDownLatch -> call.awaitOrCancel(step)
                    is Runnable -> step.run()
                    HANG -> call.awaitOrCancel(null)
                    else -> error("bad step $step")
                }
            }
        }
    }

    companion object {
        val HANG = Any()
    }
}

internal class FakeCall(
    private val transport: FakeTransport,
    val method: String,
    val body: ByteArray,
    val events: CfH2Events?,
) : CfH2Call {
    private val lock = Object()
    @Volatile var cancelled = false
        private set
    private var deadline = Long.MAX_VALUE

    override fun execute(timeoutMillis: Long): CfH2Response {
        if (timeoutMillis > 0) deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
        checkCancelled()
        if (transport.closed) throw IOException("H2 transport closed")
        transport.active.add(this)
        try {
            transport.calls.add(body)
            if (transport.traceSend && method != "HEAD") events?.requestBodyEnd()
            val response = transport.handler(FakeRequest(method, body, this))
            checkCancelled()
            val headers = HashMap<String, String>()
            for ((k, v) in response.headers) headers[k.lowercase()] = v
            if (response.body == null && "content-length" !in headers) headers["content-length"] = response.content.size.toString()
            val stream = response.body?.open(this) ?: ByteArrayInputStream(response.content)
            return CfH2Response(response.status, response.protocol, { headers[it.lowercase()] }, stream) {
                transport.active.remove(this)
            }
        } catch (e: Throwable) {
            transport.active.remove(this)
            throw e
        }
    }

    override fun cancel() {
        synchronized(lock) {
            cancelled = true
            lock.notifyAll()
        }
    }

    fun checkCancelled() {
        if (cancelled) throw IOException("Canceled")
        if (System.nanoTime() >= deadline) throw InterruptedIOException("timeout")
    }

    /** Blocks until [latch] opens (null: never), the call is cancelled, or its timeout passes. */
    fun awaitOrCancel(latch: CountDownLatch?) {
        while (true) {
            checkCancelled()
            if (latch != null && latch.count == 0L) return
            synchronized(lock) {
                if (!cancelled) lock.wait(2)
            }
        }
    }
}

/** An HTTP endpoint answering from [handler] on the calling thread (upstream: httpx.MockTransport). */
internal class FakeTransport(
    var traceSend: Boolean = true,
    val handler: (FakeRequest) -> FakeResponse,
) : CfH2Transport {
    val calls = CopyOnWriteArrayList<ByteArray>()
    val active = CopyOnWriteArrayList<FakeCall>()
    @Volatile var closed = false

    override fun newCall(method: String, body: ByteArray?, events: CfH2Events?): CfH2Call =
        FakeCall(this, method, body ?: ByteArray(0), events)

    override fun close() {
        closed = true
        for (call in active) call.cancel()
    }

    fun callTexts(): List<String> = calls.map { String(it, Charsets.ISO_8859_1) }
}

/** Client bytes for bridgeH2: fed by the test, EOF on [finish], and close() unblocks a reader. */
internal class FeedInputStream : InputStream() {
    private val chunks = LinkedBlockingQueue<ByteArray>()
    private var current = ByteArray(0)
    private var pos = 0
    @Volatile private var closed = false

    fun feed(data: ByteArray) = chunks.put(data.copyOf())
    fun finish() = chunks.put(EOF)

    override fun read(): Int {
        val one = ByteArray(1)
        return if (read(one, 0, 1) < 0) -1 else one[0].toInt() and 0xFF
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len == 0) return 0
        while (pos >= current.size) {
            if (closed) throw IOException("stream closed")
            val next = chunks.poll(5, TimeUnit.MILLISECONDS) ?: continue
            if (next === EOF) {
                chunks.put(EOF)
                return -1
            }
            current = next
            pos = 0
        }
        val n = minOf(len, current.size - pos)
        System.arraycopy(current, pos, b, off, n)
        pos += n
        return n
    }

    override fun close() {
        closed = true
    }

    private companion object {
        val EOF = ByteArray(0)
    }
}

/** What bridgeH2 writes to the client, decrypted as the client would; [onFlush] may block or fail. */
internal class CaptureOutputStream(private val decrypt: AesCtr?, var onFlush: () -> Unit = {}) : OutputStream() {
    private val lock = java.util.concurrent.locks.ReentrantLock()
    private val changed = lock.newCondition()
    private val plain = ByteArrayOutputStream()

    override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

    override fun write(b: ByteArray, off: Int, len: Int) {
        lock.withLock {
            val data = b.copyOfRange(off, off + len)
            plain.write(decrypt?.update(data) ?: data)
            changed.signalAll()
        }
    }

    override fun flush() = onFlush()

    @Volatile var closed = false
        private set

    override fun close() {
        closed = true
        lock.withLock { changed.signalAll() }
    }

    fun bytes(): ByteArray = lock.withLock { plain.toByteArray() }

    /** Waits until at least [count] bytes arrived. */
    fun awaitSize(count: Int, timeoutMs: Long = 2000): ByteArray = lock.withLock {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (plain.size() < count) {
            val left = deadline - System.nanoTime()
            if (left <= 0) break
            changed.awaitNanos(left)
        }
        plain.toByteArray()
    }
}

/**
 * The client side of the obfuscated connection after the init: [send] frames and encrypts
 * packets as a Telegram client does; [crypto] is what the proxy holds for this client.
 */
internal class NativeClient(val tag: ByteArray) {
    private val upKey = Bytes.random(32)
    private val upIv = Bytes.random(16)
    private val downKey = Bytes.random(32)
    private val downIv = Bytes.random(16)
    private val up = AesCtr(upKey, upIv)
    val down = AesCtr(downKey, downIv)
    val crypto = CryptoCtx(
        cltDec = AesCtr(upKey, upIv),
        cltEnc = AesCtr(downKey, downIv),
        tgEnc = AesCtr(Bytes.random(32), Bytes.random(16)),
        tgDec = AesCtr(Bytes.random(32), Bytes.random(16)),
    )
    val input = FeedInputStream()
    val output = CaptureOutputStream(down)

    /** Encrypted wire bytes for [plainFrames]. */
    fun encrypt(plainFrames: ByteArray): ByteArray = up.update(plainFrames)

    fun send(plainFrames: ByteArray) = input.feed(encrypt(plainFrames))

    private var readPos = 0

    /** The next whole reply frame's body (with 0xdd padding), waiting for it to arrive. */
    fun nextReply(timeoutMs: Long = 2000): ByteArray {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
        while (true) {
            val plain = output.bytes()
            if (plain.size > readPos) {
                val rest = plain.copyOfRange(readPos, plain.size)
                val headerLength = if (tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED)) {
                    if ((rest[0].toInt() and 0xFF) == 0x7F) 4 else 1
                } else 4
                val first = replies(rest, tag).firstOrNull()
                if (first != null) {
                    readPos += headerLength + first.size
                    return first
                }
            }
            val left = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            if (left <= 0) throw AssertionError("no reply frame in ${timeoutMs}ms")
            output.awaitSize(plain.size + 1, left)
        }
    }

    companion object {
        /** A client frame as Telegram clients build it, quick-ack flag optional, extra padding for 0xdd. */
        fun frame(body: ByteArray, tag: ByteArray, quick: Boolean = false, padding: Int = 0): ByteArray {
            if (tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED)) {
                val words = body.size / 4
                val flag = if (quick) 0x80 else 0
                val prefix = if (words < 127) byteArrayOf((words or flag).toByte())
                else byteArrayOf((0x7F or flag).toByte(), words.toByte(), (words ushr 8).toByte(), (words ushr 16).toByte())
                return prefix + body
            }
            val padded = if (tag.contentEquals(MtConst.PROTO_TAG_SECURE)) body + Bytes.random(padding) else body
            val length = padded.size or (if (quick) Int.MIN_VALUE else 0)
            return CfH2Framing.int32le(length) + padded
        }

        /** Splits client-side plaintext output into reply bodies (padding kept for 0xdd). */
        fun replies(plain: ByteArray, tag: ByteArray): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            var pos = 0
            while (pos < plain.size) {
                val length: Int
                if (tag.contentEquals(MtConst.PROTO_TAG_ABRIDGED)) {
                    var words = plain[pos].toInt() and 0xFF
                    pos += 1
                    if (words == 0x7F) {
                        words = (plain[pos].toInt() and 0xFF) or ((plain[pos + 1].toInt() and 0xFF) shl 8) or
                            ((plain[pos + 2].toInt() and 0xFF) shl 16)
                        pos += 3
                    }
                    length = words * 4
                } else {
                    length = Bytes.u32le(plain, pos).toInt()
                    pos += 4
                }
                if (pos + length > plain.size) break
                out.add(plain.copyOfRange(pos, pos + length))
                pos += length
            }
            return out
        }
    }
}

internal fun bytesOf(text: String): ByteArray = text.toByteArray(Charsets.ISO_8859_1)

internal fun rep(c: Char, n: Int): ByteArray = ByteArray(n) { c.code.toByte() }

internal fun rep(b: Int, n: Int): ByteArray = ByteArray(n) { b.toByte() }

internal fun cat(vararg parts: ByteArray): ByteArray {
    val out = ByteArrayOutputStream()
    for (p in parts) out.write(p)
    return out.toByteArray()
}

/** Captures ProxyLog lines while [block] runs, with verbose logging on. */
internal fun captureLogs(block: () -> Unit): List<String> {
    val lines = CopyOnWriteArrayList<String>()
    val oldSink = ProxyLog.sink
    val oldVerbose = ProxyLog.verbose
    ProxyLog.sink = { level, msg -> lines.add("${level.name} $msg") }
    ProxyLog.verbose = true
    try {
        block()
    } finally {
        ProxyLog.sink = oldSink
        ProxyLog.verbose = oldVerbose
    }
    return lines
}

/** Runs [block] on a new daemon thread. */
internal fun background(name: String = "test", block: () -> Unit): Thread =
    Thread(block, name).apply {
        isDaemon = true
        start()
    }

/** Waits until [condition] holds, polling. */
internal fun waitFor(timeoutMs: Long = 2000, what: String = "condition", condition: () -> Boolean) {
    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
    while (!condition()) {
        if (System.nanoTime() > deadline) throw AssertionError("timed out waiting for $what")
        Thread.sleep(1)
    }
}

/** The channel's requests in the order they were sent (upstream: list(channel.pending)). */
internal fun CfH2Channel.pendingTasks(): List<CfH2Task> = lane.lock.withLock { pending.keys.toList() }

/** Waits for every request pending now to finish (upstream: gather(*channel.pending)). */
internal fun CfH2Channel.awaitPending(except: CfH2Task? = null, timeoutMs: Long = 2000) {
    for (task in pendingTasks()) {
        if (task === except) continue
        if (!task.awaitDone(timeoutMs, TimeUnit.MILLISECONDS)) throw AssertionError("request did not finish")
    }
}
