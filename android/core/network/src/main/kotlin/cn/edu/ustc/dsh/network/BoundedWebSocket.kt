package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import javax.net.ssl.SSLSocket

class RelayException(val code: String = "relay.disconnected") : IllegalStateException(code)

/** Bounded RFC 6455 client framing for the fixed text-only Relay subprotocol; no extensions. */
internal class RelayFrameCodec(private val input: InputStream, private val output: OutputStream) {
    companion object { private val random = SecureRandom() }
    data class Frame(val opcode: Int, val final: Boolean, val bytes: ByteArray)
    fun read(remaining: Int): Frame {
        val first = byte(); val second = byte()
        val opcode = first and 15; val final = first and 128 != 0
        if (first and 112 != 0 || second and 128 != 0 || opcode !in setOf(0, 1, 8, 9, 10)) throw RelayException("protocol.invalid")
        var size = (second and 127).toLong()
        if (size == 126L) {
            size = (byte() * 256 + byte()).toLong()
            if (size < 126) throw RelayException("protocol.invalid")
        } else if (size == 127L) {
            size = 0
            repeat(8) { index ->
                val value = byte()
                if (index == 0 && value and 128 != 0 || size > RELAY_FRAME_BYTES) throw RelayException("protocol.frame_too_large")
                size = (size shl 8) or value.toLong()
            }
            if (size < 65536) throw RelayException("protocol.invalid")
        }
        val control = opcode >= 8
        if (control && (!final || size > 125) || size > RELAY_FRAME_BYTES || !control && size > remaining) throw RelayException("protocol.frame_too_large")
        // The advertised length is checked before allocation or payload reads.
        val bytes = ByteArray(size.toInt())
        var offset = 0
        while (offset < bytes.size) {
            val count = input.read(bytes, offset, bytes.size - offset)
            if (count <= 0) throw RelayException()
            offset += count
        }
        if (opcode == 8) validateClose(bytes)
        return Frame(opcode, final, bytes)
    }
    fun write(opcode: Int, bytes: ByteArray) {
        if (opcode !in setOf(1, 8, 10)) throw RelayException("protocol.invalid")
        if (bytes.size > RELAY_FRAME_BYTES || opcode >= 8 && bytes.size > 125) throw RelayException("protocol.frame_too_large")
        output.write(128 or opcode)
        when {
            bytes.size < 126 -> output.write(128 or bytes.size)
            bytes.size < 65536 -> { output.write(128 or 126); output.write(bytes.size ushr 8); output.write(bytes.size and 255) }
            else -> { output.write(128 or 127); repeat(8) { output.write((bytes.size.toLong() ushr ((7 - it) * 8) and 255).toInt()) } }
        }
        val mask = ByteArray(4).also(random::nextBytes); output.write(mask)
        val masked = ByteArray(bytes.size) { (bytes[it].toInt() xor mask[it % 4].toInt()).toByte() }
        output.write(masked); output.flush()
    }
    private fun byte(): Int = input.read().also { if (it < 0) throw RelayException() }
    private fun validateClose(bytes: ByteArray) {
        if (bytes.size == 1) throw RelayException("protocol.invalid")
        if (bytes.size < 2) return
        val code = ((bytes[0].toInt() and 255) shl 8) or (bytes[1].toInt() and 255)
        if (code !in 1000..1014 && code !in 3000..4999 || code in setOf(1004, 1005, 1006)) throw RelayException("protocol.invalid")
        try {
            Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes, 2, bytes.size - 2))
        } catch (_: Exception) { throw RelayException("protocol.invalid") }
    }
}

/** TLS is supplied by the standard provider with the HTTP client's trust, hostname and cipher policy. */
internal class BoundedWebSocket(private val uri: URI, private val ticket: String, tls: SSLSocket, private val closeNetwork: () -> Unit = { tls.close() }) : AutoCloseable {
    private val input = tls.inputStream.buffered(8192)
    private val output = tls.outputStream
    private val frames = RelayFrameCodec(input, output)
    private val ended = AtomicBoolean()
    private val reads = Mutex()
    private val writes = Mutex()
    private val pendingWrites = java.util.concurrent.atomic.AtomicInteger()
    private var upgraded = false
    private var window = 0L
    private var windowCount = 0
    private var fragmentDeadline = Long.MAX_VALUE

    private suspend fun <T : Any> io(timeout: Long, action: () -> T): T {
        if (ended.get()) throw RelayException("relay.closed")
        return try {
            withTimeoutOrNull(timeout) {
                suspendCancellableCoroutine { continuation ->
                    val worker = CoroutineScope(Dispatchers.IO).launch(start = CoroutineStart.LAZY) {
                        try {
                            val value = action()
                            if (continuation.isActive) continuation.resumeWith(Result.success(value))
                        } catch (error: Exception) {
                            if (continuation.isActive) continuation.resumeWith(Result.failure(if (error is RelayException) error else RelayException()))
                        }
                    }
                    continuation.invokeOnCancellation { worker.cancel(); close() }
                    worker.start()
                }
            } ?: throw RelayException("relay.timeout")
        } catch (error: Exception) { close(); throw error }
    }

    suspend fun awaitOpen() = writes.withLock {
        io(10_000) {
            if (upgraded || uri.scheme != "wss" || uri.rawQuery != null || uri.rawFragment != null || uri.rawUserInfo != null || uri.path != "/v1/realtime" || Contract.base64url(ticket).size != 32) throw RelayException("protocol.invalid")
            val key = Base64.getEncoder().encodeToString(ByteArray(16).also(SecureRandom()::nextBytes))
            val request = "GET /v1/realtime HTTP/1.1\r\nHost: ${uri.rawAuthority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: $RELAY_SUBPROTOCOL\r\nSec-WebSocket-Key: $key\r\nAuthorization: DSH-Ticket $ticket\r\n\r\n"
            output.write(request.toByteArray(Charsets.US_ASCII)); output.flush()
            val header = ByteArrayOutputStream()
            var tail = 0
            while (tail != 0x0d0a0d0a) {
                if (header.size() >= 16 * 1024) throw RelayException("protocol.frame_too_large")
                val next = input.read()
                if (next < 0 || next > 126 || next in 0..8 || next in 11..12 || next in 14..31) throw RelayException("protocol.invalid")
                header.write(next); tail = (tail shl 8) or next
            }
            val lines = header.toString("US-ASCII").split("\r\n")
            if (!Regex("HTTP/1\\.1 101(?: .*)?").matches(lines.first())) throw RelayException("auth.proof_invalid")
            val values = linkedMapOf<String, MutableList<String>>()
            for (line in lines.drop(1).filter(String::isNotEmpty)) {
                val index = line.indexOf(':')
                if (index <= 0 || line.any { it == '\r' || it == '\n' } || !Regex("[!#$%&'*+.^_`|~0-9A-Za-z-]+").matches(line.substring(0, index))) throw RelayException("protocol.invalid")
                values.getOrPut(line.substring(0, index).lowercase()) { arrayListOf() }.add(line.substring(index + 1).trim(' ', '\t'))
            }
            fun one(name: String): String = values[name]?.singleOrNull() ?: throw RelayException("protocol.invalid")
            val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray(Charsets.US_ASCII)))
            if (!one("upgrade").equals("websocket", true) || one("connection").split(',').none { it.trim().equals("upgrade", true) } ||
                one("sec-websocket-accept") != accept || one("sec-websocket-protocol") != RELAY_SUBPROTOCOL ||
                values.containsKey("sec-websocket-extensions") || values.containsKey("transfer-encoding") || values["content-length"]?.let { it != listOf("0") } == true) throw RelayException("protocol.invalid")
            upgraded = true
        }
    }
    suspend fun receive(): JsonObject = reads.withLock {
        if (!upgraded) throw RelayException("protocol.invalid")
        val message = ByteArrayOutputStream()
        var started = false
        var count = 0
        fragmentDeadline = Long.MAX_VALUE
        while (true) {
            val remainingTime = if (fragmentDeadline == Long.MAX_VALUE) 45_000 else ((fragmentDeadline - System.nanoTime()) / 1_000_000).coerceAtLeast(1)
            val frame = io(remainingTime) { frames.read(RELAY_FRAME_BYTES - message.size()) }
            val clock = System.nanoTime()
            if (clock - window >= 1_000_000_000 || window == 0L) { window = clock; windowCount = 0 }
            if (++windowCount > 200 || clock > fragmentDeadline) { close(); throw RelayException("protocol.resync_required") }
            when (frame.opcode) {
                8 -> { runCatching { write(8, frame.bytes) }; close(); currentCoroutineContext().ensureActive(); throw RelayException() }
                9 -> { write(10, frame.bytes); continue }
                10 -> continue
                1 -> { if (started) { close(); throw RelayException("protocol.invalid") }; started = true; fragmentDeadline = clock + 5_000_000_000 }
                0 -> if (!started) { close(); throw RelayException("protocol.invalid") }
            }
            if (++count > 64) { close(); throw RelayException("protocol.resync_required") }
            message.write(frame.bytes)
            if (frame.final) {
                if (ended.get()) throw RelayException("relay.closed")
                return@withLock try { relayFrame(message.toByteArray()) } catch (_: Exception) { close(); throw RelayException("protocol.invalid") }
            }
        }
        @Suppress("UNREACHABLE_CODE") throw RelayException()
    }
    suspend fun send(frame: JsonObject) {
        if (!upgraded) throw RelayException("protocol.invalid")
        val bytes = JsonDocument.of(frame).canonicalBytes()
        if (bytes.size > RELAY_FRAME_BYTES) throw RelayException("protocol.frame_too_large")
        write(1, bytes)
    }
    private suspend fun write(opcode: Int, bytes: ByteArray) {
        if (pendingWrites.incrementAndGet() > 8) { pendingWrites.decrementAndGet(); close(); throw RelayException("protocol.resync_required") }
        try { writes.withLock { io(5000) { frames.write(opcode, bytes) } } }
        finally { pendingWrites.decrementAndGet() }
    }
    override fun close() { if (ended.compareAndSet(false, true)) runCatching { closeNetwork() } }
}
