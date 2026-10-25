package cn.edu.ustc.dsh.session

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections

class CachedTranscript(val epoch: String, val savedAt: Long, records: List<SessionRecord>) {
    val transcript: SessionTranscript
    init {
        Contract.uuid(epoch)
        if (savedAt < 0 || records.size > SessionWindow.MAX_RECORDS || records.sumOf { it.weight } > SessionWindow.MAX_RETAINED_WEIGHT) throw SessionDataException("data.corrupt")
        for (i in 1 until records.size) if (records[i].seq != records[i - 1].seq + 1) throw SessionDataException("data.corrupt")
        val copy = Collections.unmodifiableList(records.toList())
        val cursor = copy.lastOrNull()?.seq ?: -1
        transcript = SessionTranscript(copy, cursor, cursor, copy.firstOrNull()?.seq?.let { it > 0 } ?: false,
            cursor, "persisted", Collections.unmodifiableList(copy.mapNotNull { it.conversationItem(cursor) }), false, true)
    }
    override fun toString() = "CachedTranscript(records=${transcript.records.size})"
}

/** Storage never grants reading authority. A client must obtain fresh resource authorization first. */
interface TranscriptCache {
    val owner: LocalDataOwner
    suspend fun loadTranscript(runtime: String, session: String, workspace: String?): CachedTranscript?
    suspend fun saveTranscript(runtime: String, session: String, workspace: String?, epoch: String, transcript: SessionTranscript, now: Long = System.currentTimeMillis())
    suspend fun removeTranscript(runtime: String, session: String)
    suspend fun removeRuntimeTranscripts(runtime: String)
    /** Apply the current authoritative directory, including after process recovery. */
    suspend fun retainTranscripts(scopes: Map<String, RelayScope>)
}
