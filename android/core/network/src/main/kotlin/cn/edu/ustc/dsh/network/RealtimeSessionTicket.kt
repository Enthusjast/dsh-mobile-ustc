package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.auth.LoginConfiguration
import cn.edu.ustc.dsh.crypto.DeviceProofSigner
import cn.edu.ustc.dsh.crypto.DeviceProofs
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean

/** Ephemeral one-use credential. Never in UI state, storage, logs or a URL. */
class RealtimeSessionTicket internal constructor(
    private val http: LoginHttp, private val configuration: LoginConfiguration, private val signer: DeviceProofSigner,
    val deviceId: String, val runtimeId: String, val grantVersion: Long, val scope: RelayScope,
    val expiresAt: Long, private val credentialExpiresAt: Long, private val token: String,
) {
    private val spent = AtomicBoolean()
    suspend fun connect(): SessionRelayConnection {
        if (!spent.compareAndSet(false, true) || System.currentTimeMillis() >= expiresAt || System.currentTimeMillis() >= credentialExpiresAt) throw RelayException("ticket.invalid")
        var socket: BoundedWebSocket? = null
        var transferred = false
        try {
            val connected = withTimeoutOrNull(15_000) {
                val uri = URI(configuration.remoteOrigin.replaceFirst("https://", "wss://") + "/v1/realtime")
                val link = http.relaySocket(uri, token)
                socket = link
                link.awaitOpen()
                val now = System.currentTimeMillis()
                val challenge = DeviceChallenge.parse(link.receive(), now, expiresAt)
                val capabilities = mutableListOf("connection.heartbeat.v1", "session.read.v1")
                if (scope.actions.any { it in setOf("message.submit", "session.cancel") }) capabilities += "command.relay.v1"
                if ("session.cancel" in scope.actions) capabilities += "session.cancel.v1"
                val hello = DeviceHello(deviceId, capabilities)
                val proof = withContext(Dispatchers.Default) { DeviceProofs.relayHandshake(signer, hello, challenge, runtimeId, System.currentTimeMillis()) }
                link.send(hello.frame(proof))
                val connection = DeviceConnection.parse(link.receive(), hello, challenge, runtimeId, grantVersion, scope, System.currentTimeMillis(), credentialExpiresAt)
                SessionRelayConnection(connection, link)
            } ?: throw RelayException("relay.handshake_timeout")
            currentCoroutineContext().ensureActive()
            transferred = true
            return connected
        } finally { if (!transferred) socket?.close() }
    }
}

/** One authenticated socket; session routing and recovery are owned by its foreground reader. */
class SessionRelayConnection internal constructor(val identity: DeviceConnection, private val socket: BoundedWebSocket) : AutoCloseable {
    private val started = System.nanoTime()
    private val lifetime = identity.leaseExpiresAt - identity.connectedAt
    private fun current() {
        val now = System.currentTimeMillis()
        if (now < identity.connectedAt || now >= identity.leaseExpiresAt || (System.nanoTime() - started) / 1_000_000 >= lifetime) { close(); throw RelayException("relay.lease_expired") }
    }
    internal suspend fun receive(): JsonObject {
        current()
        val frame = withTimeoutOrNull((identity.leaseExpiresAt - System.currentTimeMillis()).coerceAtLeast(1)) { socket.receive() }
            ?: run { close(); throw RelayException("relay.lease_expired") }
        current(); return frame
    }
    internal suspend fun send(frame: JsonObject) { current(); socket.send(frame) }
    override fun close() = socket.close()
}
