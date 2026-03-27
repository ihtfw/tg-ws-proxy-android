package org.flowseal.tgwsproxy.proxy

import android.util.Log
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

/**
 * Lightweight WebSocket client for connecting to Telegram DCs.
 * Direct port of the Python RawWebSocket class.
 */
class RawWebSocket private constructor(
    private val input: InputStream,
    private val output: OutputStream,
    private val socket: Socket
) {
    @Volatile
    private var closed = false

    companion object {
        private const val TAG = "RawWebSocket"

        const val OP_TEXT = 0x1
        const val OP_BINARY = 0x2
        const val OP_CLOSE = 0x8
        const val OP_PING = 0x9
        const val OP_PONG = 0xA

        private val random = SecureRandom()

        // Trust-all SSL context (same as Python's verify_mode=CERT_NONE)
        private val sslContext: SSLContext by lazy {
            val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
                override fun getAcceptedIssuers() = arrayOf<java.security.cert.X509Certificate>()
                override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
                override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            })
            SSLContext.getInstance("TLS").apply {
                init(null, trustAll, random)
            }
        }

        /**
         * Connect via TLS to the given IP, perform WebSocket upgrade.
         * @throws WsHandshakeError on non-101 response
         */
        fun connect(ip: String, domain: String, path: String = "/apiws", timeoutMs: Int = 10000): RawWebSocket {
            val rawSocket = Socket()
            rawSocket.connect(InetSocketAddress(ip, 443), timeoutMs)
            rawSocket.soTimeout = timeoutMs
            rawSocket.tcpNoDelay = true
            rawSocket.setSendBufferSize(256 * 1024)
            rawSocket.setReceiveBufferSize(256 * 1024)

            val sslSocket = sslContext.socketFactory.createSocket(
                rawSocket, domain, 443, true
            ) as SSLSocket
            sslSocket.startHandshake()

            val output = sslSocket.getOutputStream()
            val input = sslSocket.getInputStream()

            // WebSocket upgrade request
            val wsKeyBytes = ByteArray(16)
            random.nextBytes(wsKeyBytes)
            val wsKey = android.util.Base64.encodeToString(wsKeyBytes, android.util.Base64.NO_WRAP)

            val req = "GET $path HTTP/1.1\r\n" +
                    "Host: $domain\r\n" +
                    "Upgrade: websocket\r\n" +
                    "Connection: Upgrade\r\n" +
                    "Sec-WebSocket-Key: $wsKey\r\n" +
                    "Sec-WebSocket-Version: 13\r\n" +
                    "Sec-WebSocket-Protocol: binary\r\n" +
                    "Origin: https://web.telegram.org\r\n" +
                    "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
                    "AppleWebKit/537.36 (KHTML, like Gecko) " +
                    "Chrome/131.0.0.0 Safari/537.36\r\n" +
                    "\r\n"

            output.write(req.toByteArray(Charsets.US_ASCII))
            output.flush()

            // Read HTTP response
            val responseLines = mutableListOf<String>()
            val lineBuilder = StringBuilder()
            while (true) {
                val b = input.read()
                if (b == -1) break
                if (b == '\n'.code) {
                    val line = lineBuilder.toString().trimEnd('\r')
                    if (line.isEmpty()) break
                    responseLines.add(line)
                    lineBuilder.clear()
                } else {
                    lineBuilder.append(b.toChar())
                }
            }

            if (responseLines.isEmpty()) {
                sslSocket.close()
                throw WsHandshakeError(0, "empty response")
            }

            val firstLine = responseLines[0]
            val parts = firstLine.split(" ", limit = 3)
            val statusCode = parts.getOrNull(1)?.toIntOrNull() ?: 0

            if (statusCode == 101) {
                // Remove timeout for ongoing connection
                sslSocket.soTimeout = 0
                return RawWebSocket(input, output, sslSocket)
            }

            // Parse headers for redirect detection
            val headers = mutableMapOf<String, String>()
            for (hl in responseLines.drop(1)) {
                val colonIdx = hl.indexOf(':')
                if (colonIdx > 0) {
                    headers[hl.substring(0, colonIdx).trim().lowercase()] =
                        hl.substring(colonIdx + 1).trim()
                }
            }

            sslSocket.close()
            throw WsHandshakeError(
                statusCode, firstLine,
                headers, headers["location"]
            )
        }
    }

    fun send(data: ByteArray) {
        if (closed) throw java.io.IOException("WebSocket closed")
        val frame = buildFrame(OP_BINARY, data, mask = true)
        synchronized(output) {
            output.write(frame)
            output.flush()
        }
    }

    fun sendBatch(parts: List<ByteArray>) {
        if (closed) throw java.io.IOException("WebSocket closed")
        synchronized(output) {
            for (part in parts) {
                output.write(buildFrame(OP_BINARY, part, mask = true))
            }
            output.flush()
        }
    }

    /**
     * Receive the next data frame. Handles ping/pong/close internally.
     * Returns payload bytes, or null on clean close.
     */
    fun recv(): ByteArray? {
        while (!closed) {
            val (opcode, payload) = readFrame()

            when (opcode) {
                OP_CLOSE -> {
                    closed = true
                    try {
                        val reply = buildFrame(
                            OP_CLOSE,
                            if (payload.size >= 2) payload.copyOfRange(0, 2) else ByteArray(0),
                            mask = true
                        )
                        synchronized(output) {
                            output.write(reply)
                            output.flush()
                        }
                    } catch (_: Exception) {}
                    return null
                }
                OP_PING -> {
                    try {
                        val pong = buildFrame(OP_PONG, payload, mask = true)
                        synchronized(output) {
                            output.write(pong)
                            output.flush()
                        }
                    } catch (_: Exception) {}
                }
                OP_PONG -> { /* ignore */ }
                OP_TEXT, OP_BINARY -> return payload
                else -> { /* unknown opcode, skip */ }
            }
        }
        return null
    }

    fun close() {
        if (closed) return
        closed = true
        try {
            synchronized(output) {
                output.write(buildFrame(OP_CLOSE, ByteArray(0), mask = true))
                output.flush()
            }
        } catch (_: Exception) {}
        try { socket.close() } catch (_: Exception) {}
    }

    val isClosed: Boolean get() = closed || socket.isClosed

    private fun readFrame(): Pair<Int, ByteArray> {
        val hdr = readExactly(2)
        val opcode = hdr[0].toInt() and 0x0F
        var length = (hdr[1].toInt() and 0x7F).toLong()

        if (length == 126L) {
            val ext = readExactly(2)
            length = ByteBuffer.wrap(ext).short.toLong() and 0xFFFF
        } else if (length == 127L) {
            val ext = readExactly(8)
            length = ByteBuffer.wrap(ext).long
        }

        val isMasked = (hdr[1].toInt() and 0x80) != 0
        if (isMasked) {
            val maskKey = readExactly(4)
            val payload = readExactly(length.toInt())
            return opcode to xorMask(payload, maskKey)
        }

        return opcode to readExactly(length.toInt())
    }

    private fun readExactly(n: Int): ByteArray {
        val buf = ByteArray(n)
        var offset = 0
        while (offset < n) {
            val read = input.read(buf, offset, n - offset)
            if (read == -1) throw java.io.EOFException("Connection closed")
            offset += read
        }
        return buf
    }

    private fun buildFrame(opcode: Int, data: ByteArray, mask: Boolean): ByteArray {
        val length = data.size
        val fb = (0x80 or opcode).toByte()

        val header: ByteArray
        val headerSize: Int

        if (!mask) {
            when {
                length < 126 -> {
                    header = ByteArray(2)
                    header[0] = fb
                    header[1] = length.toByte()
                    headerSize = 2
                }
                length < 65536 -> {
                    header = ByteArray(4)
                    header[0] = fb
                    header[1] = 126.toByte()
                    ByteBuffer.wrap(header, 2, 2).putShort(length.toShort())
                    headerSize = 4
                }
                else -> {
                    header = ByteArray(10)
                    header[0] = fb
                    header[1] = 127.toByte()
                    ByteBuffer.wrap(header, 2, 8).putLong(length.toLong())
                    headerSize = 10
                }
            }
            val frame = ByteArray(headerSize + length)
            System.arraycopy(header, 0, frame, 0, headerSize)
            System.arraycopy(data, 0, frame, headerSize, length)
            return frame
        }

        // Masked frame
        val maskKey = ByteArray(4)
        random.nextBytes(maskKey)
        val masked = xorMask(data, maskKey)

        when {
            length < 126 -> {
                header = ByteArray(6)
                header[0] = fb
                header[1] = (0x80 or length).toByte()
                System.arraycopy(maskKey, 0, header, 2, 4)
                headerSize = 6
            }
            length < 65536 -> {
                header = ByteArray(8)
                header[0] = fb
                header[1] = (0x80 or 126).toByte()
                ByteBuffer.wrap(header, 2, 2).putShort(length.toShort())
                System.arraycopy(maskKey, 0, header, 4, 4)
                headerSize = 8
            }
            else -> {
                header = ByteArray(14)
                header[0] = fb
                header[1] = (0x80 or 127).toByte()
                ByteBuffer.wrap(header, 2, 8).putLong(length.toLong())
                System.arraycopy(maskKey, 0, header, 10, 4)
                headerSize = 14
            }
        }

        val frame = ByteArray(headerSize + length)
        System.arraycopy(header, 0, frame, 0, headerSize)
        System.arraycopy(masked, 0, frame, headerSize, length)
        return frame
    }

    private fun xorMask(data: ByteArray, mask: ByteArray): ByteArray {
        if (data.isEmpty()) return data
        val result = ByteArray(data.size)
        for (i in data.indices) {
            result[i] = (data[i].toInt() xor mask[i % 4].toInt()).toByte()
        }
        return result
    }
}

class WsHandshakeError(
    val statusCode: Int,
    val statusLine: String,
    val headers: Map<String, String> = emptyMap(),
    val location: String? = null
) : Exception("HTTP $statusCode: $statusLine") {
    val isRedirect: Boolean get() = statusCode in listOf(301, 302, 303, 307, 308)
}
