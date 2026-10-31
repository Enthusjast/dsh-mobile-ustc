package cn.edu.ustc.dsh.mobile

import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.TextFieldValue
import cn.edu.ustc.dsh.command.CommandOwner

/** An accepted local-data owner and the exact remote resource, never an authorization grant. */
class ConversationResource(val owner: CommandOwner, val hostId: String, val runtimeId: String, val sessionId: String) {
    override fun equals(other: Any?): Boolean = other is ConversationResource && owner.fingerprint == other.owner.fingerprint &&
        hostId == other.hostId && runtimeId == other.runtimeId && sessionId == other.sessionId
    override fun hashCode(): Int = (((owner.fingerprint.hashCode() * 31 + hostId.hashCode()) * 31 + runtimeId.hashCode()) * 31 + sessionId.hashCode())
    override fun toString() = "ConversationResource"
}

data class MessageComposerState(val resource: ConversationResource, val value: TextFieldValue = TextFieldValue(), val mode: String = "queue", val revision: Long = 0) {
    override fun toString() = "MessageComposerState(revision=$revision)"
}

/** The button captures this immutable revision. Neither IME actions nor quote insertion submits it. */
data class MessageSubmission(val draft: MessageComposerState, val sendNow: Boolean) {
    override fun toString() = "MessageSubmission(revision=${draft.revision})"
}

/** Foreground memory only. No Bundle, preferences, database, or saved-state representation. */
internal class ConversationDrafts(private val maxEntries: Int = 16, private val maxCharacters: Int = 262_144) {
    private val entries = linkedMapOf<ConversationResource, MessageComposerState>()
    private var revision = 0L
    private var failedInput: MessageComposerState? = null
    fun open(resource: ConversationResource): MessageComposerState = entries.remove(resource)?.also { entries[resource] = it }
        ?: MessageComposerState(resource, revision = ++revision).also { entries[resource] = it; trim(resource) }
    fun current(resource: ConversationResource): MessageComposerState? = entries[resource]
    fun edit(candidate: MessageComposerState): MessageComposerState? {
        val current = entries[candidate.resource] ?: return null
        if (candidate.revision != current.revision || candidate.mode !in setOf("queue", "steer") || candidate.value.text.length > 65_536) return null
        if (candidate.value == current.value && candidate.mode == current.mode) return current
        return candidate.copy(revision = ++revision).also { entries.remove(candidate.resource); entries[candidate.resource] = it; trim(candidate.resource) }
    }
    fun saved(original: MessageComposerState): MessageComposerState? {
        val current = entries[original.resource] ?: return null
        if (current.revision != original.revision) return null
        return current.copy(value = TextFieldValue(), revision = ++revision).also { entries[original.resource] = it }
    }
    fun retainFailed(original: MessageComposerState): MessageComposerState? {
        val current = entries[original.resource] ?: return null
        if (current.revision == original.revision || current.value.text.length + original.value.text.length > maxCharacters) return null
        return original.copy(value = original.value.copy(composition = null)).also {
            failedInput = it
            trim(current.resource)
        }
    }
    fun recoverable(resource: ConversationResource): MessageComposerState? = failedInput?.takeIf { it.resource == resource }
    fun resolveFailure(original: MessageComposerState, restore: Boolean): MessageComposerState? {
        if (failedInput !== original) return null
        val current = entries[original.resource] ?: return null
        failedInput = null
        return if (restore) edit(current.copy(value = original.value, mode = original.mode)) else current
    }
    fun dismissFailure() { failedInput = null }
    fun clear(pickerException: MessageComposerState? = null) {
        entries.clear()
        failedInput = null
        ++revision
        pickerException?.let { entries[it.resource] = it }
    }
    fun revokeRuntime(runtimeId: String) {
        entries.keys.removeAll { it.runtimeId == runtimeId }
        if (failedInput?.resource?.runtimeId == runtimeId) failedInput = null
    }
    private fun trim(keep: ConversationResource) {
        while (entries.size > maxEntries || entries.values.sumOf { it.value.text.length } + (failedInput?.value?.text?.length ?: 0) > maxCharacters) {
            val oldest = entries.keys.firstOrNull { it != keep } ?: break
            entries.remove(oldest)
            if (failedInput?.resource == oldest) failedInput = null
        }
    }
}

internal fun MessageComposerState.withLocalQuote(text: String): MessageComposerState {
    val quote = text.lineSequence().joinToString("\n") { "> $it" }
    val prefix = value.text.takeIf { it.isNotEmpty() }?.let { "$it\n\n" }.orEmpty()
    val combined = prefix + quote + "\n\n"
    return copy(value = TextFieldValue(combined, TextRange(combined.length)))
}
