package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.*
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicBoolean

data class CommandOutboxState(val records: List<PendingCommand> = emptyList(), val connected: Boolean = false, val sending: Boolean = false, val error: String? = null)

/** Shares the reader's authenticated socket; never writes automatically after a reconnect. */
class SessionCommands internal constructor(private val api: RemoteApi, private val journal: CommandJournal, private val runtime: String, private val session: String,
    private val scopeGrant: RelayScope, owner: CoroutineScope) : AutoCloseable {
    private class Endpoint(val generation: Long, val connection: SessionRelayConnection, val epoch: String)
    private class Send(val id: String, val generation: Long)
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Default)
    private val mutable = MutableStateFlow(CommandOutboxState())
    private val closed = AtomicBoolean()
    val state: StateFlow<CommandOutboxState> = mutable.asStateFlow()
    private val endpoint = AtomicReference<Endpoint?>()
    private val generation = AtomicLong()
    private val sendQueue = Channel<Send>(8)
    private val refreshQueue = Channel<Unit>(Channel.CONFLATED)
    init {
        scope.launch { sender() }
        scope.launch {
            while (isActive) {
                refresh()
                withTimeoutOrNull(5000) { refreshQueue.receive() }
            }
        }
    }
    internal fun ready(connection: SessionRelayConnection, epoch: String) {
        if (!scope.isActive) return
        endpoint.set(Endpoint(generation.incrementAndGet(), connection, epoch))
        update { it.copy(connected = canSend(connection)) }; refreshQueue.trySend(Unit)
    }
    internal fun disconnected() {
        generation.incrementAndGet(); endpoint.set(null)
        while (sendQueue.tryReceive().isSuccess) { /* Retire old-generation queued intent. */ }
        update { it.copy(connected = false, sending = false) }
    }
    private fun canSend(connection: SessionRelayConnection) = "command.relay.v1" in connection.identity.capabilities && "message.submit" in scopeGrant.actions && "command.status" in scopeGrant.actions
    suspend fun submit(mode: String, text: String, sendNow: Boolean = true): String {
        if (!scope.isActive || "message.submit" !in scopeGrant.actions || "command.status" !in scopeGrant.actions) throw RemoteRequestException("access.denied")
        val intent = CommandIntent.message(UUID.randomUUID().toString(), runtime, session, mode, text)
        journal.create(intent); refreshQueue.trySend(Unit)
        if (sendNow) sendPending(intent.requestId)
        return intent.requestId
    }
    suspend fun cancel(expectedEpoch: String): String {
        val target = endpoint.get() ?: throw RelayException("runtime.offline")
        if (target.epoch != Contract.uuid(expectedEpoch)) throw CommandDataException("runtime.changed")
        if ("session.cancel" !in scopeGrant.actions || "session.cancel.v1" !in target.connection.identity.capabilities || "command.relay.v1" !in target.connection.identity.capabilities) throw RemoteRequestException("access.denied")
        val intent = CommandIntent.cancel(UUID.randomUUID().toString(), runtime, session, target.epoch)
        journal.create(intent); refreshQueue.trySend(Unit); enqueue(intent.requestId, target)
        return intent.requestId
    }
    fun sendPending(id: String) {
        Contract.uuid(id)
        val target = endpoint.get() ?: return
        if (canSend(target.connection)) enqueue(id, target)
    }
    private fun enqueue(id: String, target: Endpoint) {
        if (sendQueue.trySend(Send(id, target.generation)).isFailure) update { it.copy(error = "command.busy") }
    }
    fun query() { refreshQueue.trySend(Unit) }
    internal fun hint(receipt: CommandReceipt) {
        // Device-facing wire receipts omit the origin identifier. Confirm durable
        // facts using REST, which independently binds the registered DPoP device.
        if (receipt.sessionId == session && mutable.value.records.any { it.intent.requestId == receipt.requestId && it.attempts > 0 }) query()
    }
    internal suspend fun failed(id: String, code: String): Boolean {
        Contract.uuid(id)
        val record = journal.list(runtime, session).firstOrNull { it.intent.requestId == id && it.attempts > 0 } ?: return false
        journal.uncertain(record.intent.requestId, if (code == "runtime.changed") code else "command.delivery_unconfirmed")
        query()
        return true
    }
    suspend fun discard(id: String) { journal.discard(id); refreshQueue.trySend(Unit) }
    private suspend fun sender() {
        for (event in sendQueue) {
            val target = endpoint.get() ?: continue
            if (target.generation != event.generation) continue
            var attempted = false
            try {
                val known = journal.list(runtime, session).firstOrNull { it.intent.requestId == event.id } ?: throw CommandDataException("command.not_found")
                if (known.intent.kind.wire !in scopeGrant.actions || known.intent.kind == CommandKind.CANCEL && known.intent.epoch != target.epoch) throw CommandDataException("runtime.changed")
                if (known.attempts > 0) {
                    val proof = api.commandStatus(event.id, journal.owner.deviceId)
                    if (endpoint.get() !== target) throw RelayException("relay.disconnected")
                    journal.rearm(event.id, proof)
                }
                val record = journal.beginAttempt(event.id); attempted = true
                if (record.intent.runtimeId != runtime || record.intent.sessionId != session || record.intent.epoch != null && record.intent.epoch != target.epoch) throw CommandDataException("runtime.changed")
                currentCoroutineContext().ensureActive()
                if (endpoint.get() !== target) throw RelayException("relay.disconnected")
                update { it.copy(sending = true, error = null) }
                target.connection.send(record.intent.frame()); query()
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                val code = if (error is CommandDataException) error.code else "command.delivery_unconfirmed"
                if (attempted) runCatching { journal.uncertain(event.id, code) }
                update { it.copy(error = code) }
            } finally { update { it.copy(sending = false) }; query() }
        }
    }
    private suspend fun refresh() {
        try {
            var records = journal.list(runtime, session)
            update { it.copy(records = records) }
            val target = endpoint.get() ?: return
            if ("command.status" !in scopeGrant.actions) return
            for (record in records) {
                if (endpoint.get() !== target || !scope.isActive) return
                if (record.attempts == 0L || record.remote in setOf(RemoteCommandState.SETTLED, RemoteCommandState.REJECTED)) continue
                try {
                    val status = api.commandStatus(record.intent.requestId, journal.owner.deviceId)
                    currentCoroutineContext().ensureActive()
                    if (endpoint.get() !== target) return
                    journal.record(status)
                } catch (error: CancellationException) { throw error }
                catch (error: Exception) { journal.uncertain(record.intent.requestId, if (error is RemoteRequestException && error.code == "access.denied") "command.status_unavailable" else "command.delivery_unconfirmed") }
                delay(75)
            }
            records = journal.list(runtime, session)
            update { it.copy(records = records) }
        } catch (error: CancellationException) { throw error }
        catch (_: Exception) { update { it.copy(error = "data.unavailable") } }
    }
    @Synchronized private fun update(transform: (CommandOutboxState) -> CommandOutboxState) { if (!closed.get()) mutable.update(transform) }
    @Synchronized override fun close() {
        if (!closed.compareAndSet(false, true)) return
        disconnected(); scope.cancel(); sendQueue.cancel(); refreshQueue.cancel(); mutable.value = CommandOutboxState()
    }
}
