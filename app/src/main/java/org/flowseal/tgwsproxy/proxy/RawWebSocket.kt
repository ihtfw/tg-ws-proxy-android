package org.flowseal.tgwsproxy.proxy

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLException
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** A non-101 answer to the WebSocket upgrade. */
class WsHandshakeError(
    val statusCode: Int,
    val statusLine: String,
    val headers: Map<String, String> = emptyMap(),
    val location: String? = null,
) : IOException("HTTP $statusCode: $statusLine") {
    val isRedirect: Boolean get() = statusCode in setOf(301, 302, 303, 307, 308)
}

/**
 * A minimal client WebSocket over TLS (or plain TCP), binary frames only
 * (upstream proxy/raw_websocket.py).
 */
class RawWebSocket private constructor(
    private val socket: Socket,
    private val input: InputStream,
    private val output: OutputStream,
) : AutoCloseable {

    @Volatile private var closed = false
    private val frag = ByteArrayOutputStream()
    private val writeLock = Any()

    val isClosed: Boolean get() = closed || socket.isClosed || socket.isInputShutdown

    /**
     * For an idle pooled socket: closed, or the peer sent something before our init, which from
     * Telegram is only a close frame.
     */
    fun looksDead(): Boolean {
        if (isClosed) return true
        return try {
            input.available() > 0
        } catch (_: IOException) {
            true
        }
    }

    fun send(data: ByteArray) {
        if (closed) throw IOException("WebSocket closed")
        val frame = buildFrame(OP_BINARY, data, mask = true)
        synchronized(writeLock) {
            output.write(frame)
            output.flush()
        }
    }

    fun sendBatch(parts: List<ByteArray>) {
        if (closed) throw IOException("WebSocket closed")
        synchronized(writeLock) {
            for (p in parts) output.write(buildFrame(OP_BINARY, p, mask = true))
            output.flush()
        }
    }

    /** The next data message, or null once the peer closes. Answers pings itself. */
    fun recv(): ByteArray? {
        while (!closed) {
            val frame = readFrame()
            when (frame.opcode) {
                OP_CLOSE -> {
                    closed = true
                    ProxyLog.d { "WS OP_CLOSE from upstream: ${parseClose(frame.payload)}" }
                    try {
                        val code = if (frame.payload.size >= 2) frame.payload.copyOfRange(0, 2) else ByteArray(0)
                        synchronized(writeLock) {
                            output.write(buildFrame(OP_CLOSE, code, mask = true))
                            output.flush()
                        }
                    } catch (_: Exception) {
                    }
                    return null
                }
                OP_PING -> {
                    try {
                        synchronized(writeLock) {
                            output.write(buildFrame(OP_PONG, frame.payload, mask = true))
                            output.flush()
                        }
                    } catch (_: Exception) {
                    }
                }
                OP_PONG -> {}
                OP_CONT, OP_TEXT, OP_BINARY -> {
                    if (frame.fin && frag.size() == 0) return frame.payload
                    frag.write(frame.payload)
                    if (frag.size() > MAX_MESSAGE_LEN) throw IOException("WS message too large: ${frag.size()} bytes")
                    if (!frame.fin) continue
                    val message = frag.toByteArray()
                    frag.reset()
                    return message
                }
                else -> {}
            }
        }
        return null
    }

    override fun close() {
        try {
            if (!closed) {
                closed = true
                try {
                    synchronized(writeLock) {
                        output.write(buildFrame(OP_CLOSE, ByteArray(0), mask = true))
                        output.flush()
                    }
                } catch (_: Exception) {
                }
            }
        } finally {
            socket.closeQuietly()
        }
    }

    private class Frame(val opcode: Int, val payload: ByteArray, val fin: Boolean)

    private fun readFrame(): Frame {
        val hdr = input.readExactly(2)
        val fin = (hdr[0].toInt() and 0x80) != 0
        val opcode = hdr[0].toInt() and 0x0F
        var length = (hdr[1].toInt() and 0x7F).toLong()
        if (length == 126L) {
            length = Bytes.u16be(input.readExactly(2), 0).toLong()
        } else if (length == 127L) {
            val ext = input.readExactly(8)
            length = 0
            for (b in ext) length = (length shl 8) or (b.toLong() and 0xFF)
        }
        if (length < 0 || length > MAX_MESSAGE_LEN) throw IOException("WS frame too large: $length bytes")
        return if ((hdr[1].toInt() and 0x80) != 0) {
            val mask = input.readExactly(4)
            Frame(opcode, xorMask(input.readExactly(length.toInt()), mask), fin)
        } else {
            Frame(opcode, input.readExactly(length.toInt()), fin)
        }
    }

    companion object {
        const val OP_CONT = 0x0
        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA
        const val MAX_MESSAGE_LEN = 16 * 1024 * 1024

        private val CLOSE_REASONS = mapOf(
            1000 to "normal", 1001 to "going_away", 1002 to "protocol_error",
            1003 to "unsupported_data", 1006 to "abnormal", 1007 to "bad_data",
            1008 to "policy_violation", 1009 to "too_big", 1010 to "missing_extension",
            1011 to "internal_error",
        )

        /** Buffer size applied to new sockets (the "Buffer KB" setting). */
        @Volatile var socketBufferSize: Int = 256 * 1024

        /**
         * Connects to [host] (an IP or a name), upgrades to a WebSocket at [path] with Host [domain].
         * TLS: SNI [sni] or [domain]; the certificate chain is always checked, the name only when
         * no [sni] is given (fronting presents another name on purpose). [secure] false: port 80.
         * @throws WsHandshakeError on any status other than 101.
         */
        fun connect(
            host: String,
            domain: String,
            timeoutMs: Int = 10_000,
            path: String = MtConst.WS_PATH,
            sni: String? = null,
            secure: Boolean = true,
        ): RawWebSocket {
            val raw = Socket()
            var sock: Socket = raw
            try {
                raw.tcpNoDelay = true
                try {
                    raw.sendBufferSize = socketBufferSize
                    raw.receiveBufferSize = socketBufferSize
                } catch (_: Exception) {
                }
                raw.connect(InetSocketAddress(host, if (secure) 443 else 80), minOf(timeoutMs, 10_000))
                raw.soTimeout = timeoutMs
                if (secure) {
                    val serverName = sni ?: domain
                    val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
                    val ssl = factory.createSocket(raw, serverName, 443, true) as SSLSocket
                    sock = ssl
                    ssl.startHandshake()
                    if (sni == null && !HostCheck.matches(ssl.session, domain)) {
                        throw SSLException("certificate does not match $domain")
                    }
                }
                val input = BufferedInputStream(sock.getInputStream(), 65536)
                val output = sock.getOutputStream()

                val req = "GET $path HTTP/1.1\r\n" +
                    "Host: $domain\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: ${Bytes.base64(Bytes.random(16))}\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "Sec-WebSocket-Protocol: binary\r\n" +
                    "\r\n"
                output.write(req.toByteArray(Charsets.US_ASCII))
                output.flush()

                val lines = ArrayList<String>()
                while (true) {
                    val line = readLine(input) ?: break
                    if (line.isEmpty()) break
                    lines.add(line)
                }
                if (lines.isEmpty()) throw WsHandshakeError(0, "empty response")
                val first = lines[0]
                val status = first.split(' ', limit = 3).getOrNull(1)?.toIntOrNull() ?: 0
                if (status == 101) {
                    sock.soTimeout = 0
                    return RawWebSocket(sock, input, output)
                }
                val headers = HashMap<String, String>()
                for (hl in lines.drop(1)) {
                    val i = hl.indexOf(':')
                    if (i > 0) headers[hl.substring(0, i).trim().lowercase()] = hl.substring(i + 1).trim()
                }
                throw WsHandshakeError(status, first, headers, headers["location"])
            } catch (e: Throwable) {
                sock.closeQuietly()
                raw.closeQuietly()
                throw e
            }
        }

        private fun readLine(input: InputStream): String? {
            val sb = StringBuilder()
            while (true) {
                val b = input.read()
                if (b < 0) return if (sb.isEmpty()) null else sb.toString()
                if (b == '\n'.code) return sb.toString().trimEnd('\r')
                sb.append(b.toChar())
                if (sb.length > 8192) throw IOException("HTTP header line too long")
            }
        }

        fun parseClose(payload: ByteArray): String {
            if (payload.size < 2) return "-"
            val code = Bytes.u16be(payload, 0)
            val text = String(payload, 2, payload.size - 2, Charsets.UTF_8)
            val name = CLOSE_REASONS[code]
            return "code=$code ${if (name != null) "$text ($name)" else text}"
        }

        fun buildFrame(opcode: Int, data: ByteArray, mask: Boolean): ByteArray {
            val length = data.size
            val fb = (0x80 or opcode).toByte()
            val maskBit = if (mask) 0x80 else 0
            val lenBytes = when {
                length < 126 -> 0
                length < 65536 -> 2
                else -> 8
            }
            val headerLen = 2 + lenBytes + (if (mask) 4 else 0)
            val frame = ByteArray(headerLen + length)
            frame[0] = fb
            when (lenBytes) {
                0 -> frame[1] = (maskBit or length).toByte()
                2 -> {
                    frame[1] = (maskBit or 126).toByte()
                    frame[2] = (length ushr 8).toByte()
                    frame[3] = length.toByte()
                }
                else -> {
                    frame[1] = (maskBit or 127).toByte()
                    val l = length.toLong()
                    for (i in 0 until 8) frame[2 + i] = (l ushr (56 - 8 * i)).toByte()
                }
            }
            if (!mask) {
                System.arraycopy(data, 0, frame, headerLen, length)
                return frame
            }
            val key = Bytes.random(4)
            System.arraycopy(key, 0, frame, 2 + lenBytes, 4)
            for (i in 0 until length) {
                frame[headerLen + i] = (data[i].toInt() xor key[i and 3].toInt()).toByte()
            }
            return frame
        }

        fun xorMask(data: ByteArray, mask: ByteArray): ByteArray {
            for (i in data.indices) data[i] = (data[i].toInt() xor mask[i and 3].toInt()).toByte()
            return data
        }
    }
}
