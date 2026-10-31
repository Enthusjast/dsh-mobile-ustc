package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

interface FileInputSource : AutoCloseable { val name: String; fun open(): InputStream }
enum class UploadPhase { NEEDS_SOURCE, REGISTERING, UPLOADING, SCANNING, WAITING, READY, BOUND, REJECTED, EXPIRED, ERROR }
data class UploadView(val stored: StoredFileUpload, val phase: UploadPhase, val status: RemoteFileStatus? = null, val bytes: Long = 0, val error: String? = null) {
    fun ready() = phase == UploadPhase.READY && stored.messageId == null && status?.readyForMessage() == true
}
data class SessionUploadState(val rows: List<UploadView> = emptyList(), val selected: Set<String> = emptySet(), val busy: Boolean = false, val hashing: Boolean = false, val error: String? = null)

internal fun toggleUploadSelection(state: SessionUploadState, id: String): SessionUploadState = when {
    id in state.selected -> state.copy(selected = state.selected - id, error = null)
    state.rows.firstOrNull { it.stored.intent.requestId == id }?.ready() != true -> state
    state.selected.size >= 15 -> state.copy(error = "file.too_many")
    else -> state.copy(selected = state.selected + id, error = null)
}

/** Foreground workflow; only immutable intent metadata survives a closed view. */
class SessionUploads internal constructor(private val api: RemoteApi, private val journal: FileUploadJournal, val runtimeId: String, val sessionId: String, private val workspace: String?, owner: CoroutineScope) : AutoCloseable {
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Default)
    private val mutable = MutableStateFlow(SessionUploadState())
    val state: StateFlow<SessionUploadState> = mutable.asStateFlow()
    private val closed = AtomicBoolean()
    private val lock = Any()
    private var task: Job? = null
    private var input: FileInputSource? = null
    @Volatile private var activeId: String? = null
    private val operationErrors = java.util.concurrent.ConcurrentHashMap<String, String>()
    init {
        Contract.uuid(runtimeId); Contract.uuid(sessionId); workspace?.let(Contract::uuid)
        scope.launch { while (isActive) { reload(); delay(1000) } }
    }
    fun select(source: FileInputSource, resumeId: String? = null) = selectInternal(source, resumeId, null)
    fun selectImage(source: FileInputSource, image: ImageUploadMetadata, resumeId: String? = null) = selectInternal(source, resumeId, image)
    private fun selectInternal(source: FileInputSource, resumeId: String?, image: ImageUploadMetadata?) = synchronized(lock) {
        if (closed.get() || task?.isActive == true) { runCatching { source.close() }; return@synchronized }
        input = source
        activeId = resumeId
        update { it.copy(busy = true, hashing = true, error = null) }
        task = scope.launch {
            var id = resumeId
            try {
                val prior = resumeId?.let { requested -> journal.uploads(runtimeId, sessionId).firstOrNull { it.intent.requestId == requested } ?: throw CommandDataException("file.upload_not_found") }
                if (prior?.messageId != null) throw CommandDataException("file.already_bound")
                if (prior != null && ((prior.intent.image == null) != (image == null) || image != null && prior.intent.image?.same(image) != true)) throw RemoteRequestException("file.integrity_mismatch")
                val manifest = fingerprint(source, prior?.intent?.manifest?.name ?: source.name)
                if (prior != null && !prior.intent.manifest.same(manifest)) throw RemoteRequestException("file.integrity_mismatch")
                val intent = prior?.intent ?: FileUploadIntent(UUID.randomUUID().toString(), runtimeId, sessionId, workspace, manifest, image)
                val stored = journal.createUpload(intent)
                id = intent.requestId; activeId = id; operationErrors.remove(id)
                awaitLocal(stored, UploadPhase.REGISTERING)
                update { it.copy(hashing = false) }
                val prepared = api.registerFile(runtimeId, sessionId, id, manifest)
                val known = journal.registeredUpload(id, prepared.file.id) // durable before anonymous bytes
                awaitLocal(known, if (prepared.canUpload) UploadPhase.UPLOADING else phase(known, prepared.file), prepared.file)
                if (prepared.canUpload) {
                    api.uploadFile(prepared, source::open) { count -> updateRow(id) { it.copy(bytes = count) } }
                    val committed = api.commitFile(prepared.file.id)
                    awaitLocal(known, phase(known, committed), committed)
                }
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) {
                val code = code(error)
                if (id != null) { operationErrors[id] = code; updateRow(id) { it.copy(phase = UploadPhase.ERROR, error = code) } }
                update { it.copy(error = code) }
            } finally {
                runCatching { source.close() }
                synchronized(lock) { if (input === source) input = null; activeId = null }
                update { it.copy(busy = false, hashing = false) }
                reload()
            }
        }
    }
    fun query(id: String) {
        Contract.uuid(id)
        update { it.copy(error = null) }
        scope.launch {
            try {
                val old = journal.uploads(runtimeId, sessionId).firstOrNull { it.intent.requestId == id } ?: return@launch
                operationErrors.remove(id)
                if (old.fileId == null) {
                    val prepared = api.registerFile(runtimeId, sessionId, old.intent.requestId, old.intent.manifest)
                    journal.registeredUpload(id, prepared.file.id)
                }
                reload()
            } catch (error: CancellationException) { throw error }
            catch (error: Exception) { update { it.copy(error = code(error)) } }
        }
    }
    fun remove(id: String) {
        Contract.uuid(id)
        synchronized(lock) { if (activeId == id) { task?.cancel(); runCatching { input?.close() } } }
        scope.launch {
            try { journal.removeUpload(id); operationErrors.remove(id); update { it.copy(selected = it.selected - id) }; reload() }
            catch (error: CancellationException) { throw error }
            catch (error: Exception) { update { it.copy(error = code(error)) } }
        }
    }
    fun cancelTransfer() = synchronized(lock) { task?.cancel(); runCatching { input?.close() }; Unit }
    fun toggle(id: String) {
        update { state -> toggleUploadSelection(state, id) }
    }
    fun selectedFiles(): List<String> = selectedAttachments(false)
    fun selectedImages(): List<String> = selectedAttachments(true)
    private fun selectedAttachments(images: Boolean): List<String> {
        val state = mutable.value
        val views = state.selected.map { id -> state.rows.firstOrNull { it.stored.intent.requestId == id } ?: throw RemoteRequestException("file.staging_required") }
        if (views.any { !it.ready() }) throw RemoteRequestException("file.staging_required")
        return views.filter { (it.stored.intent.image != null) == images }.map { it.stored.fileId ?: throw RemoteRequestException("file.state_changed") }
    }
    fun messageSaved() { update { it.copy(selected = emptySet()) }; scope.launch { reload() } }
    private suspend fun fingerprint(source: FileInputSource, name: String): FileManifest = withContext(Dispatchers.IO) {
        val hash = MessageDigest.getInstance("SHA-256")
        var size = 0L
        source.open().use { stream ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                currentCoroutineContext().ensureActive()
                val count = stream.read(buffer); if (count < 0) break
                if (count == 0 || size + count > MAX_FILE_BYTES) throw RemoteRequestException("file.too_large")
                size += count; hash.update(buffer, 0, count)
            }
        }
        FileManifest(name, size, hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) })
    }
    private suspend fun reload() {
        if (!scope.isActive) return
        try {
            val stored = journal.uploads(runtimeId, sessionId)
            val rows = stored.map { row ->
                val previous = mutable.value.rows.firstOrNull { it.stored.intent.requestId == row.intent.requestId }
                if (row.intent.requestId == activeId && previous != null) return@map previous.copy(stored = row)
                if (row.messageId != null) return@map UploadView(row, UploadPhase.BOUND)
                val fileId = row.fileId
                if (fileId == null) return@map UploadView(row, if (operationErrors.containsKey(row.intent.requestId)) UploadPhase.ERROR else UploadPhase.NEEDS_SOURCE, error = operationErrors[row.intent.requestId])
                try {
                    val current = api.fileStatus(fileId)
                    if (current.runtimeId != runtimeId || current.sessionId != sessionId || !current.manifest.same(row.intent.manifest)) throw RemoteRequestException("auth.identity_mismatch")
                    val error = operationErrors[row.intent.requestId]
                    UploadView(row, if (error != null && current.state == FileTransferState.UPLOADING) UploadPhase.ERROR else phase(row, current), current, error = error ?: current.error)
                } catch (error: CancellationException) { throw error }
                catch (error: Exception) { UploadView(row, UploadPhase.ERROR, error = code(error)) }
            }
            update { it.copy(rows = rows, selected = it.selected.intersect(rows.filter(UploadView::ready).map { row -> row.stored.intent.requestId }.toSet())) }
        } catch (error: CancellationException) { throw error }
        catch (error: Exception) { update { it.copy(error = code(error)) } }
    }
    private fun phase(row: StoredFileUpload, file: RemoteFileStatus) = when {
        row.messageId != null || file.delivery?.state == FileDeliveryState.BOUND -> UploadPhase.BOUND
        file.state == FileTransferState.REJECTED -> UploadPhase.REJECTED
        file.state == FileTransferState.EXPIRED -> UploadPhase.EXPIRED
        file.state == FileTransferState.UPLOADING -> UploadPhase.NEEDS_SOURCE
        file.state == FileTransferState.SCANNING -> UploadPhase.SCANNING
        file.readyForMessage() -> UploadPhase.READY
        else -> UploadPhase.WAITING
    }
    private suspend fun awaitLocal(row: StoredFileUpload, phase: UploadPhase, status: RemoteFileStatus? = null) {
        update { state -> state.copy(rows = state.rows.filterNot { it.stored.intent.requestId == row.intent.requestId } + UploadView(row, phase, status)) }
    }
    private fun code(error: Exception) = when (error) { is CommandDataException -> error.code; is RemoteRequestException -> error.code; is ProtocolException -> "file.invalid"; else -> "file.unavailable" }
    private fun updateRow(id: String, transform: (UploadView) -> UploadView) { update { state -> state.copy(rows = state.rows.map { if (it.stored.intent.requestId == id) transform(it) else it }) } }
    private fun update(transform: (SessionUploadState) -> SessionUploadState) { if (!closed.get()) mutable.update(transform) }
    override fun close() = synchronized(lock) {
        if (!closed.compareAndSet(false, true)) return@synchronized
        task?.cancel(); runCatching { input?.close() }; input = null; scope.cancel(); mutable.value = SessionUploadState()
    }
}
