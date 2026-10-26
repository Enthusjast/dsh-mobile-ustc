package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal class MemoryFileExportJournal(override val owner: CommandOwner) : FileExportJournal {
    private val rows = linkedMapOf<String, StoredFileExport>()
    private val lock = Mutex()
    var failCreate = false
    override suspend fun createExport(intent: FileExportIntent, now: Long): StoredFileExport = lock.withLock {
        if (failCreate) throw CommandDataException("data.unavailable")
        rows[intent.requestId]?.let { if (it.intent.digest != intent.digest) throw CommandDataException("file.request_conflict"); return@withLock it }
        StoredFileExport(intent, null, null, now, now).also { rows[intent.requestId] = it }
    }
    override suspend fun exports(runtime: String, session: String) = lock.withLock { rows.values.filter { it.intent.runtimeId == runtime && it.intent.sessionId == session } }
    override suspend fun registeredExport(id: String, file: RemoteExportStatus, now: Long): StoredFileExport = lock.withLock {
        val old = rows[id] ?: throw CommandDataException("file.export_not_found")
        if (!old.intent.matches(file) || old.fileId?.let { it != file.id } == true || old.manifest?.let { !it.same(file.manifest) } == true) throw CommandDataException("file.request_conflict")
        StoredFileExport(old.intent, file.id, file.manifest, old.createdAt, maxOf(now, old.updatedAt)).also { rows[id] = it }
    }
    override suspend fun removeExport(id: String) { lock.withLock { rows.remove(id) } }
}
