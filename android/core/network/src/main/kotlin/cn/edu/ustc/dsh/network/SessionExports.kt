package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

data class ExportView(val stored: StoredFileExport, val status: RemoteExportStatus? = null, val error: String? = null)
data class SessionExportState(val connected: Boolean = false, val page: ExportPage? = null, val listing: Boolean = false,
    val preparing: Boolean = false, val rows: List<ExportView> = emptyList(), val error: String? = null)

/** One foreground view. No automatic re-admission of an ambiguous export. */
class SessionExports internal constructor(private val api: RemoteApi, private val journal: FileExportJournal, val runtimeId: String, val sessionId: String,
    private val workspace: String?, private val grant: RelayScope, owner: CoroutineScope) : AutoCloseable {
    private class Endpoint(val connection: SessionRelayConnection, val epoch: String)
    private class Pending(val endpoint: Endpoint, val type: String, val reply: CompletableDeferred<JsonObject>)
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Default)
    private val mutable = MutableStateFlow(SessionExportState())
    val state = mutable.asStateFlow()
    private val endpoint = AtomicReference<Endpoint?>()
    private val pending = ConcurrentHashMap<String, Pending>()
    private val closed = AtomicBoolean()
    private val listing = AtomicBoolean()
    private val preparing = AtomicBoolean()
    private val reloadLock = Mutex()
    private val mutations = Mutex()
    init {
        listOf(runtimeId, sessionId).forEach(Contract::uuid)
        grant.session(sessionId, workspace, setOf("session.read", "file.download"))
        scope.launch { while (isActive) { reload(); delay(2000) } }
    }
    @Synchronized internal fun ready(connection: SessionRelayConnection, epoch: String) {
        if (closed.get() || endpoint.get()?.connection === connection) return
        if (FILE_EXPORT_CAPABILITY !in connection.identity.capabilities) { disconnected(); return }
        Contract.uuid(epoch)
        endpoint.set(Endpoint(connection, epoch)); update { it.copy(connected = true, page = null) }
    }
    @Synchronized internal fun disconnected() {
        endpoint.set(null)
        pending.values.forEach { it.reply.completeExceptionally(RemoteRequestException("file.export_reconcile")) }; pending.clear()
        update { it.copy(connected = false, page = null, listing = false) }
    }
    private fun current(target: Endpoint) {
        if (closed.get() || endpoint.get() !== target) throw RemoteRequestException("file.export_stale")
        target.connection.checkCurrent()
    }
    private fun frame(type: String, id: String, target: Endpoint, payload: JsonObject) = jsonObject("v" to 1L.json(), "type" to type.json(), "request_id" to id.json(),
        "runtime_id" to runtimeId.json(), "runtime_epoch" to target.epoch.json(), "session_id" to sessionId.json(), "payload" to payload)
    private suspend fun exchange(type: String, id: String, target: Endpoint, payload: JsonObject): JsonObject {
        current(target)
        val wait = Pending(target, type, CompletableDeferred())
        if (pending.putIfAbsent(id, wait) != null) throw RemoteRequestException("file.request_conflict")
        try {
            target.connection.send(frame(type, id, target, payload))
            return withTimeoutOrNull(if (type == "file.exports.list") 20_000 else 300_000) { wait.reply.await() }
                ?: throw RemoteRequestException("file.export_reconcile")
        } finally { pending.remove(id, wait) }
    }
    /** Called only by the existing socket receiver. No additional receiver or disk I/O. */
    internal fun accept(frame: JsonObject) {
        val type = frame.string("type")
        relayEnvelope(frame, type, "v", "type", "request_id", "runtime_id", "runtime_epoch", "session_id", "payload")
        if (type !in setOf("file.exports.result", "file.export.accepted", "file.export.error")) throw ProtocolException()
        val target = endpoint.get() ?: return
        if (frame.string("runtime_id") != runtimeId || frame.string("session_id") != sessionId || frame.string("runtime_epoch") != target.epoch) throw ProtocolException()
        val id = Contract.uuid(frame.string("request_id")); val payload = frame.obj("payload")
        when (type) {
            "file.exports.result" -> ExportPage.parse(payload)
            "file.export.accepted" -> { payload.exactKeys("file"); RemoteExportStatus.parse(payload.obj("file")) }
            else -> { payload.exactKeys("code"); if (payload.string("code") !in errors) throw ProtocolException() }
        }
        val wait = pending[id] ?: return // A later scanning hint is recovered by authenticated REST.
        if (wait.endpoint !== target || type != "file.export.error" && type != if (wait.type == "file.exports.list") "file.exports.result" else "file.export.accepted") throw ProtocolException()
        if (type == "file.export.error") wait.reply.completeExceptionally(RemoteRequestException(payload.string("code"))) else wait.reply.complete(payload)
    }
    internal fun error(frame: JsonObject, code: String): Boolean {
        val id = (frame.fields["request_id"] as? JsonString)?.value ?: return false
        val wait = pending[id] ?: return false
        wait.reply.completeExceptionally(RemoteRequestException(if (code in errors) code else "protocol.invalid")); return true
    }
    fun browse(source: ExportSource? = null, more: Boolean = false) {
        val target = endpoint.get() ?: return
        if (!listing.compareAndSet(false, true)) return
        val old = mutable.value.page
        if (source != null && (old?.items?.none { it === source } != false || !source.directory || !source.current()) || more && (source != null || old?.cursor == null)) { listing.set(false); return }
        val directory = if (more) old?.directoryId else source?.id
        val cursor = if (more) old?.cursor else null
        update { it.copy(listing = true, error = null, page = null) }
        scope.launch {
            try {
                val selector = jsonObject(*listOfNotNull(directory?.let { "directory_id" to it.json() }, cursor?.let { "cursor" to it.json() }).toTypedArray())
                val page = ExportPage.parse(exchange("file.exports.list", UUID.randomUUID().toString(), target, selector))
                current(target)
                if (page.directoryId != directory || page.items.any { it.origin == ExportOrigin.WORKSPACE_ARTIFACT && workspace !in grant.workspaces }) throw ProtocolException()
                update { it.copy(page = page) }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { if (endpoint.get() === target) update { it.copy(error = code(error)) } }
            finally { listing.set(false); update { it.copy(listing = false) } }
        }
    }
    fun request(source: ExportSource) {
        val target = endpoint.get() ?: return
        if (mutable.value.page?.items?.none { it === source } != false || source.directory || source.unavailable || !source.current() || !preparing.compareAndSet(false, true)) return
        update { it.copy(preparing = true, error = null) }
        scope.launch {
            try {
                current(target)
                val intent = FileExportIntent(UUID.randomUUID().toString(), runtimeId, sessionId, target.epoch, source.id, workspace, source.origin, source.name, source.sizeBytes!!)
                journal.createExport(intent) // FULL synchronous encrypted WAL commit precedes the mutation.
                currentCoroutineContext().ensureActive(); current(target)
                val reply = exchange("file.export.request", intent.requestId, target, jsonObject("source_id" to source.id.json()))
                val file = RemoteExportStatus.parse(reply.obj("file"))
                mutations.withLock { journal.registeredExport(intent.requestId, file) }
                reload()
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { update { it.copy(error = code(error)) }; reload() }
            finally { preparing.set(false); update { it.copy(preparing = false) } }
        }
    }
    fun cancel(id: String) {
        Contract.uuid(id)
        scope.launch {
            val row = journal.exports(runtimeId, sessionId).firstOrNull { it.intent.requestId == id } ?: return@launch
            val target = endpoint.get() ?: return@launch
            if (row.intent.epoch != target.epoch) return@launch
            try {
                current(target)
                target.connection.send(frame("file.export.cancel", id, target, jsonObject()))
                pending[id]?.reply?.completeExceptionally(RemoteRequestException("file.export_reconcile"))
                update { it.copy(error = "file.export_cancelled") }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { update { it.copy(error = code(error)) } }
        }
    }
    fun query() { scope.launch { reload() } }
    fun remove(id: String) { scope.launch { mutations.withLock { journal.removeExport(Contract.uuid(id)) }; reload() } }
    private suspend fun reload() = reloadLock.withLock {
        if (closed.get()) return@withLock
        try {
            val rows = journal.exports(runtimeId, sessionId).map { stored ->
                try {
                    val file = stored.fileId?.let { api.exportStatus(it) } ?: api.exportRequestStatus(stored.intent.requestId)
                    val saved = mutations.withLock { journal.registeredExport(stored.intent.requestId, file) }
                    ExportView(saved, file)
                } catch (error: CancellationException) { throw error }
                catch (error: Exception) { ExportView(stored, error = code(error)) }
            }
            update { it.copy(rows = rows) }
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) { update { it.copy(error = code(error)) } }
    }
    private fun code(error: Exception) = when (error) { is CommandDataException -> error.code; is RemoteRequestException -> error.code; is ProtocolException -> "protocol.invalid"; else -> "file.unavailable" }
    private fun update(transform: (SessionExportState) -> SessionExportState) { if (!closed.get()) mutable.update(transform) }
    @Synchronized override fun close() {
        if (!closed.compareAndSet(false, true)) return
        disconnected(); scope.cancel(); mutable.value = SessionExportState()
    }
    companion object { private val errors = setOf("access.denied", "runtime.changed", "runtime.offline", "protocol.unsupported", "protocol.invalid", "rate.limited", "file.export_unavailable",
        "file.export_changed", "file.export_unsupported", "file.too_large", "file.unavailable", "file.scanner_unavailable", "file.quota_exceeded", "file.state_changed", "command.request_conflict") }
}
