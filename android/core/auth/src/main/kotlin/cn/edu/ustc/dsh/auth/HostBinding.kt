package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import java.util.Collections

class HostBindingException(val code: String) : IllegalStateException(code)
class BindingWorkspace(val id: String, val reference: String)

/** Public review facts only. The confirmation secret never belongs in view or saved state. */
class HostBindingDetails private constructor(private val document: JsonDocument, val workspaces: List<BindingWorkspace>) {
    private val root get() = document.root
    val id get() = root.string("enrollment_id")
    val organizationId get() = root.string("organization_id")
    val organizationName get() = root.string("organization_name")
    val hostId get() = root.string("host_id")
    val hostAlias get() = root.string("host_alias")
    val installationId get() = root.string("installation_id")
    val keyThumbprint get() = root.string("installation_key_jkt")
    val runtimeId get() = root.string("runtime_id")
    val profile get() = root.string("profile_ref")
    val dshVersion get() = (root.fields["dsh_version"] as? JsonString)?.value ?: ""
    val protocolVersion get() = root.integer("protocol_version", 1, 32)
    val state get() = root.string("state")
    val expiresAt get() = relayTime(root.string("expires_at"))
    val hostConfirmed get() = (root["host_confirmed"] as JsonBoolean).value
    val userConfirmed get() = (root["user_confirmed"] as JsonBoolean).value
    val confirmedByMe get() = (root["user_confirmed_by_me"] as JsonBoolean).value
    val reviewHash = JsonDocument.of(JsonObject(root.fields.filterKeys { it !in setOf("state", "host_confirmed", "user_confirmed", "user_confirmed_by_me") })).sha256()
    fun expired(now: Long = System.currentTimeMillis()) = state == "expired" || state in setOf("pending", "user_confirmed") && now >= expiresAt
    fun canConfirm(now: Long = System.currentTimeMillis()) = protocolVersion == 1L && state == "pending" && !userConfirmed && !expired(now)
    override fun toString() = "HostBindingDetails(state=$state)"

    companion object {
        private val required = setOf("enrollment_id", "request_id", "organization_id", "organization_name", "host_id", "host_alias", "installation_id", "installation_key_jkt", "runtime_id", "profile_ref", "protocol_version", "state", "expires_at", "host_confirmed", "user_confirmed", "user_confirmed_by_me", "workspaces")
        private val versions = setOf("dsh_version", "application_version", "plugin_version")
        fun parse(root: JsonObject, organizationId: String, enrollmentId: String): HostBindingDetails {
            if (!root.fields.keys.containsAll(required) || root.fields.keys.any { it !in required && it !in versions }) throw ProtocolException()
            for (field in listOf("enrollment_id", "request_id", "organization_id", "host_id", "installation_id", "runtime_id")) Contract.uuid(root.string(field))
            if (root.string("enrollment_id") != Contract.uuid(enrollmentId)) throw HostBindingException("binding.identity_mismatch")
            if (root.string("organization_id") != Contract.uuid(organizationId)) throw HostBindingException("binding.organization_mismatch")
            for (field in listOf("organization_name", "host_alias")) {
                val name = Contract.boundedText(root.string(field), 640)
                if (name.codePointCount(0, name.length) > 160) throw ProtocolException()
            }
            reference(root.string("profile_ref"))
            Contract.nonce(root.string("installation_key_jkt"))
            for (field in versions) if (field in root.fields) root.string(field).let { if (it.isNotEmpty()) Contract.boundedText(it, 128) }
            root.integer("protocol_version", 1, 32); relayTime(root.string("expires_at"))
            val host = boolean(root, "host_confirmed"); val user = boolean(root, "user_confirmed"); val mine = boolean(root, "user_confirmed_by_me")
            if (mine && !user) throw ProtocolException()
            when (root.string("state")) {
                "pending" -> if (user) throw ProtocolException()
                "user_confirmed" -> if (!user || host) throw ProtocolException()
                "approved" -> if (!user || !host) throw ProtocolException()
                "expired", "denied", "cancelled" -> Unit
                else -> throw ProtocolException()
            }
            val entries = root.array("workspaces")
            if (entries.size > 64) throw ProtocolException()
            val workspaces = entries.map { item ->
                val workspace = item as? JsonObject ?: throw ProtocolException()
                workspace.exactKeys("workspace_id", "reference")
                BindingWorkspace(Contract.uuid(workspace.string("workspace_id")), reference(workspace.string("reference")))
            }
            if (workspaces.map { it.id }.toSet().size != workspaces.size || workspaces.map { it.reference }.toSet().size != workspaces.size) throw ProtocolException()
            return HostBindingDetails(JsonDocument.of(root), Collections.unmodifiableList(workspaces))
        }
        private fun reference(value: String): String = value.also {
            if (!Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}").matches(it) || it in setOf(".", "..")) throw ProtocolException()
        }
        private fun boolean(root: JsonObject, field: String) = (root[field] as? JsonBoolean)?.value ?: throw ProtocolException()
    }
}
