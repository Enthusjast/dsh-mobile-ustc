package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import cn.edu.ustc.dsh.session.SessionTranscript
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import java.io.OutputStream
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Encoded preview bytes never enter a disk cache or a serializable state. */
class VerifiedMediaBytes internal constructor(val reference: VisibleMediaReference, private val bytes: ByteArray) : AutoCloseable {
    private var closed = false
    @Synchronized fun <T> read(action: (ByteArray) -> T): T {
        if (closed) throw RemoteRequestException("image.stale")
        return action(bytes)
    }
    @Synchronized override fun close() { if (!closed) { closed = true; bytes.fill(0) } }
    override fun toString() = "VerifiedMediaBytes"
}
data class SessionMediaState(val canPreview: Boolean = false, val reference: VisibleMediaReference? = null, val loading: Boolean = false,
    val bytes: VerifiedMediaBytes? = null, val error: String? = null)

/** Reuses the sole SessionReader socket and the independently authorized export/scanner/download pipeline. */
class SessionMedia internal constructor(private val api: RemoteApi, private val exports: SessionExports?, owner: CoroutineScope) : AutoCloseable {
    private class Endpoint(val binding: SessionActionBinding, val alive: () -> Boolean, val send: suspend (JsonObject) -> Unit, @Volatile var snapshot: SessionTranscript)
    private class Pending(val endpoint: Endpoint, val reference: VisibleMediaReference, val reply: CompletableDeferred<ExportSource>)
    private val scope = CoroutineScope(SupervisorJob(owner.coroutineContext[Job]) + Dispatchers.Default)
    private val mutable = MutableStateFlow(SessionMediaState())
    val state: StateFlow<SessionMediaState> = mutable.asStateFlow()
    private val endpoint = AtomicReference<Endpoint?>()
    private val pending = ConcurrentHashMap<String, Pending>()
    private val closed = AtomicBoolean()
    private val generation = AtomicLong()
    @Volatile private var enabled = false
    private var task: Job? = null

    internal fun connected(capabilities: Set<String>, allowed: Boolean) {
        enabled = allowed && exports != null && SESSION_MEDIA_CAPABILITY in capabilities && FILE_EXPORT_CAPABILITY in capabilities
        if (!enabled) disconnected("protocol.unsupported")
    }
    @Synchronized internal fun ready(binding: SessionActionBinding, snapshot: SessionTranscript, alive: () -> Boolean, send: suspend (JsonObject) -> Unit) {
        if (!enabled || closed.get()) return
        val old = endpoint.get()
        if (old?.binding == binding) old.snapshot = snapshot else {
            dismiss()
            endpoint.set(Endpoint(binding, alive, send, snapshot))
        }
        mutable.update { it.copy(canPreview = true) }
        mutable.value.reference?.let { if (!isCurrent(it)) dismiss() }
    }
    private fun contains(target: Endpoint, reference: VisibleMediaReference): Boolean {
        val snapshot = target.snapshot
        return snapshot.records.any { record -> record.seq == reference.nativeSeq && record.seq <= snapshot.persistedThrough && !record.replacement && record.blocks.any { it.media === reference } } &&
            snapshot.items.any { item -> item.persisted && !item.live && item.blocks.any { it.media === reference } }
    }
    fun isCurrent(reference: VisibleMediaReference): Boolean {
        val target = endpoint.get() ?: return false
        return !closed.get() && enabled && target.alive() && contains(target, reference)
    }
    private fun current(target: Endpoint, reference: VisibleMediaReference, operation: Long) {
        if (generation.get() != operation || endpoint.get() !== target || !isCurrent(reference)) throw RemoteRequestException("image.stale")
    }
    @Synchronized fun open(reference: VisibleMediaReference) {
        dismiss()
        val target = endpoint.get()
        if (target == null || !isCurrent(reference)) {
            mutable.value = SessionMediaState(enabled, reference, error = "image.stale")
            return
        }
        val operation = generation.get()
        mutable.value = SessionMediaState(true, reference, loading = true)
        task = scope.launch {
            var encoded: ByteArray? = null
            var published: VerifiedMediaBytes? = null
            try {
                current(target, reference, operation)
                val request = UUID.randomUUID().toString()
                val wait = Pending(target, reference, CompletableDeferred())
                if (pending.putIfAbsent(request, wait) != null) throw ProtocolException()
                val source = try {
                    target.send(target.binding.envelope("session.media.resolve", request,
                        jsonObject("sync_id" to target.binding.syncId.json(), "reference" to reference.json())))
                    withTimeout(7000) { wait.reply.await() }
                } finally { pending.remove(request, wait) }
                current(target, reference, operation)
                val file = exports!!.prepareMedia(source, reference) { current(target, reference, operation) }
                current(target, reference, operation)
                val buffer = ByteArray(reference.manifest.sizeBytes.toInt())
                encoded = buffer
                var count = 0
                val sink = object : OutputStream() {
                    override fun write(value: Int) {
                        current(target, reference, operation)
                        if (count >= buffer.size) throw RemoteRequestException("file.integrity_mismatch")
                        buffer[count++] = value.toByte()
                    }
                    override fun write(bytes: ByteArray, offset: Int, length: Int) {
                        current(target, reference, operation)
                        if (offset < 0 || length < 0 || offset > bytes.size - length || length > buffer.size - count) throw RemoteRequestException("file.integrity_mismatch")
                        bytes.copyInto(buffer, count, offset, offset + length); count += length
                    }
                }
                api.downloadExport(file, { sink }, { current(target, reference, operation) })
                current(target, reference, operation)
                if (count != buffer.size) throw RemoteRequestException("file.integrity_mismatch")
                published = VerifiedMediaBytes(reference, buffer)
                synchronized(this@SessionMedia) {
                    current(target, reference, operation)
                    mutable.value = SessionMediaState(true, reference, bytes = published)
                    encoded = null
                }
            } catch (error: CancellationException) { throw error }
            catch (error: OutOfMemoryError) {
                if (generation.get() == operation && !closed.get()) mutable.value = SessionMediaState(enabled, reference, error = "image.memory_limited")
            }
            catch (error: Exception) {
                if (generation.get() == operation && !closed.get()) mutable.value = SessionMediaState(enabled, reference, error = when (error) {
                    is RemoteRequestException -> error.code
                    is ProtocolException -> "protocol.invalid"
                    else -> "image.unavailable"
                })
            } finally {
                encoded?.fill(0)
                if (generation.get() != operation) published?.close()
            }
        }
    }
    internal fun accept(frame: JsonObject): Boolean {
        val type = frame.string("type")
        if (type != "session.media.result" && type != "session.media.error") return false
        val binding = SessionActionBinding.parseFrame(frame)
        val target = endpoint.get() ?: return true
        if (target.binding != binding) return true
        val payload = frame.obj("payload")
        val id = Contract.uuid(frame.string("request_id"))
        val wait = pending[id]
        if (type == "session.media.error") {
            payload.exactKeys("code")
            val code = payload.string("code")
            if (code !in errors) throw ProtocolException()
            if (wait?.endpoint === target) wait.reply.completeExceptionally(RemoteRequestException(code))
        } else {
            payload.exactKeys("reference", "source")
            val reference = VisibleMediaReference.parse(payload.obj("reference"))
            val source = ExportSource.parse(payload.obj("source"))
            if (source.directory || source.unavailable || source.origin != ExportOrigin.SESSION_ATTACHMENT || source.name != reference.manifest.name || source.sizeBytes != reference.manifest.sizeBytes) throw ProtocolException()
            if (wait != null) {
                if (wait.endpoint !== target || !wait.reference.same(reference) || !isCurrent(wait.reference)) throw ProtocolException()
                wait.reply.complete(source)
            }
        }
        return true
    }
    internal fun error(frame: JsonObject, code: String): Boolean {
        val id = (frame.fields["request_id"] as? JsonString)?.value ?: return false
        val wait = pending[id] ?: return false
        wait.reply.completeExceptionally(RemoteRequestException(if (code in errors) code else "protocol.invalid"))
        return true
    }
    internal fun tick() { mutable.value.reference?.let { if (!isCurrent(it)) dismiss() } }
    @Synchronized fun dismiss() {
        generation.incrementAndGet(); task?.cancel(); task = null
        pending.values.forEach { it.reply.completeExceptionally(RemoteRequestException("image.stale")) }; pending.clear()
        mutable.value.bytes?.close()
        mutable.value = SessionMediaState(enabled && endpoint.get()?.alive?.invoke() == true)
    }
    @Synchronized internal fun disconnected(code: String = "runtime.offline") {
        endpoint.set(null); dismiss()
        mutable.value = SessionMediaState(error = code)
    }
    @Synchronized override fun close() {
        if (!closed.compareAndSet(false, true)) return
        enabled = false; disconnected(); scope.cancel(); mutable.value = SessionMediaState()
    }
    companion object {
        private val errors = setOf("access.denied", "runtime.changed", "runtime.offline", "protocol.unsupported", "protocol.invalid", "protocol.resync_required", "rate.limited",
            "file.export_unavailable", "file.export_changed", "file.export_unsupported", "file.too_large", "file.unavailable", "file.state_changed", "session.persistence_unavailable")
    }
}
