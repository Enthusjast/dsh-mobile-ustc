package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.net.URI
import java.net.Socket
import java.security.MessageDigest
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.SSLSocket

class BoundedWebSocketTest {
    private class Peer(hostname: String = "localhost", action: (Socket) -> Unit) : AutoCloseable {
        private val certificate = HeldCertificate.Builder().addSubjectAlternativeName(hostname).build()
        private val serverTLS = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        private val clientTLS = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        private val server = serverTLS.sslContext().serverSocketFactory.createServerSocket(0) as SSLServerSocket
        private val accepted = AtomicReference<Socket?>()
        val uri = URI("wss://localhost:${server.localPort}/v1/realtime")
        val http = LoginHttp.forTests(OkHttpClient.Builder().sslSocketFactory(clientTLS.sslSocketFactory(), clientTLS.trustManager).build())
        fun proxied() = LoginHttp.forTests(OkHttpClient.Builder().sslSocketFactory(clientTLS.sslSocketFactory(), clientTLS.trustManager)
            .proxy(java.net.Proxy(java.net.Proxy.Type.HTTP, java.net.InetSocketAddress("127.0.0.1", 1))).build())
        val done = CompletableFuture<Unit>()
        init {
            Thread({
                try { server.accept().use { socket -> accepted.set(socket); socket.soTimeout = 10_000; (socket as SSLSocket).startHandshake(); action(socket); done.complete(Unit) } }
                catch (error: Throwable) { done.completeExceptionally(error) }
            }, "relay-fixture-peer").apply { isDaemon = true; start() }
        }
        override fun close() { accepted.get()?.close(); server.close() }
    }
    private fun upgrade(socket: Socket, protocol: String = RELAY_SUBPROTOCOL, acceptSuffix: String = "") {
        val header = ByteArrayOutputStream()
        var tail = 0
        while (tail != 0x0d0a0d0a) {
            val byte = socket.getInputStream().read(); check(byte >= 0 && header.size() < 16 * 1024)
            header.write(byte); tail = (tail shl 8) or byte
        }
        val lines = header.toString("US-ASCII").split("\r\n")
        check(lines.first() == "GET /v1/realtime HTTP/1.1")
        check(lines.single { it.startsWith("Authorization: ") } == "Authorization: DSH-Ticket ${"A".repeat(43)}")
        val key = lines.single { it.startsWith("Sec-WebSocket-Key: ") }.substringAfter(": ")
        val accept = Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-1").digest((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").toByteArray()))
        socket.getOutputStream().write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: $accept$acceptSuffix\r\nSec-WebSocket-Protocol: $protocol\r\n\r\n".toByteArray())
        socket.getOutputStream().flush()
    }
    private fun frame(socket: Socket, opcode: Int, final: Boolean, bytes: ByteArray) {
        val output = socket.getOutputStream()
        output.write((if (final) 128 else 0) or opcode)
        when {
            bytes.size < 126 -> output.write(bytes.size)
            bytes.size < 65536 -> { output.write(126); output.write(bytes.size ushr 8); output.write(bytes.size and 255) }
            else -> { output.write(127); repeat(8) { output.write((bytes.size.toLong() ushr ((7 - it) * 8) and 255).toInt()) } }
        }
        output.write(bytes); output.flush()
    }

    @Test fun fragmentedUnicodeAndInterleavedControlFramesProduceOneCompleteJsonObject(): Unit = runBlocking {
        Peer { socket ->
            upgrade(socket)
            val bytes = "{\"text\":\"中文🙂\"}".toByteArray()
            val boundary = bytes.indexOf(0xe4.toByte()) + 1 // Deliberately split a UTF-8 scalar.
            frame(socket, 1, false, bytes.copyOfRange(0, boundary))
            frame(socket, 9, true, byteArrayOf(7, 8))
            frame(socket, 0, true, bytes.copyOfRange(boundary, bytes.size))
            val input = socket.getInputStream()
            check(input.read() == 0x8a)
            check(input.read() == 0x82)
            val mask = ByteArray(4); java.io.DataInputStream(input).readFully(mask)
            check(((input.read() xor mask[0].toInt()) and 255) == 7)
            check(((input.read() xor mask[1].toInt()) and 255) == 8)
            Thread.sleep(100)
        }.use { peer ->
            val link = peer.http.relaySocket(peer.uri, "A".repeat(43))
            link.use {
                it.awaitOpen()
                assertEquals("中文🙂", withTimeout(3000) { it.receive() }.string("text"))
                peer.done.get(3, TimeUnit.SECONDS)
            }
        }
    }

    @Test fun excessiveAdvertisedPayloadAndContinuationCountsCloseWithoutPartialDelivery(): Unit = runBlocking {
        for (mode in listOf("huge", "many", "binary", "masked", "utf8")) {
            Peer { socket ->
                upgrade(socket)
                when (mode) {
                    "huge" -> socket.getOutputStream().write(byteArrayOf(0x81.toByte(), 127, 0, 0, 0, 1, 0, 0, 0, 0))
                    "many" -> { frame(socket, 1, false, byteArrayOf()); repeat(64) { frame(socket, 0, false, byteArrayOf()) } }
                    "binary" -> socket.getOutputStream().write(byteArrayOf(0x82.toByte(), 0))
                    "masked" -> socket.getOutputStream().write(byteArrayOf(0x81.toByte(), 0x80.toByte()))
                    "utf8" -> frame(socket, 1, true, byteArrayOf(123, 34, 0xc0.toByte(), 34, 58, 49, 125))
                }
                socket.getOutputStream().flush()
                Thread.sleep(300)
            }.use { peer ->
                peer.http.relaySocket(peer.uri, "A".repeat(43)).use { link ->
                    link.awaitOpen()
                    assertThrows(RelayException::class.java) { runBlocking { withTimeout(2000) { link.receive() } } }
                }
            }
        }
    }

    @Test fun cancellationInterruptsAStalledUpgradeAndTlsHostnameMismatchIsRejected(): Unit = runBlocking {
        Peer { socket -> Thread.sleep(1000) }.use { peer ->
            val link = peer.http.relaySocket(peer.uri, "A".repeat(43))
            assertThrows(TimeoutCancellationException::class.java) { runBlocking { withTimeout(100) { link.awaitOpen() } } }
            assertThrows(RelayException::class.java) { runBlocking { link.receive() } }
        }
        Peer("other.invalid") { _ -> throw AssertionError("Unverified TLS peer must receive no ticket") }.use { peer ->
            assertThrows(RelayException::class.java) { runBlocking { peer.http.relaySocket(peer.uri, "A".repeat(43)) } }
        }
    }

    @Test fun maximumSizedValidJsonIsAcceptedButBareHeaderControlsAreRejected(): Unit = runBlocking {
        val text = "a".repeat(RELAY_FRAME_BYTES - 11)
        val bytes = "{\"text\":\"$text\"}".toByteArray()
        assertEquals(RELAY_FRAME_BYTES, bytes.size)
        Peer { socket -> upgrade(socket); frame(socket, 1, true, bytes) }.use { peer ->
            peer.http.relaySocket(peer.uri, "A".repeat(43)).use { link ->
                link.awaitOpen(); assertEquals(text, link.receive().string("text"))
            }
        }
        Peer { socket -> upgrade(socket, acceptSuffix = "\r") }.use { peer ->
            peer.http.relaySocket(peer.uri, "A".repeat(43)).use { link ->
                assertEquals("protocol.invalid", assertThrows(RelayException::class.java) { runBlocking { link.awaitOpen() } }.code)
            }
        }
    }

    @Test fun aStalledFragmentExpiresAsATransportFailureWhileCallerCancellationStaysCancellation(): Unit = runBlocking {
        Peer { socket -> upgrade(socket); frame(socket, 1, false, "{\"text\":".toByteArray()); Thread.sleep(6500) }.use { peer ->
            peer.http.relaySocket(peer.uri, "A".repeat(43)).use { link ->
                link.awaitOpen()
                assertEquals("relay.timeout", assertThrows(RelayException::class.java) { runBlocking { link.receive() } }.code)
            }
        }
    }

    @Test fun configuredProxyIsRejectedBeforeDirectTransportInsteadOfBeingSilentlyBypassed(): Unit = runBlocking {
        Peer { _ -> throw AssertionError("A configured proxy must not be bypassed") }.use { peer ->
            assertEquals("network.proxy_unsupported", assertThrows(RelayException::class.java) { runBlocking { peer.proxied().relaySocket(peer.uri, "A".repeat(43)) } }.code)
        }
    }
}
