package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*

class RuntimeDirectoryEntry private constructor(val id: String, val hostId: String, val organizationId: String?, val dshVersion: String,
    val protocolVersion: Long?, val scope: RelayScope?, val grantVersion: Long?, val role: String?, val expiresAt: Long?) {
    fun canList(now: Long = System.currentTimeMillis()): Boolean = protocolVersion == 1L && scope?.actions?.contains("session.list") == true && (expiresAt == null || expiresAt > now)
    companion object {
        fun parse(root: JsonObject): RuntimeDirectoryEntry {
            val organization = if ("organization_id" in root.fields) Contract.uuid(root.string("organization_id")) else null
            val version = if ("dsh_version" in root.fields) root.string("dsh_version").also { if (it.isNotEmpty()) Contract.boundedText(it, 128) } else ""
            val protocol = if ("protocol_version" in root.fields) root.integer("protocol_version", 1, 32) else null
            val access = if ("access" in root.fields) root.obj("access") else null
            if (access == null) return RuntimeDirectoryEntry(Contract.uuid(root.string("id")), Contract.uuid(root.string("host_id")), organization, version, protocol, null, null, null, null)
            if (access.fields.keys !in listOf(setOf("role", "grant_version", "scope"), setOf("role", "grant_version", "scope", "expires_at"))) throw ProtocolException()
            val role = access.string("role")
            if (role !in setOf("viewer", "operator", "owner")) throw ProtocolException()
            val scope = RelayScope.parse(access.obj("scope"))
            val expires = if ("expires_at" in access.fields) relayTime(access.string("expires_at")) else null
            return RuntimeDirectoryEntry(Contract.uuid(root.string("id")), Contract.uuid(root.string("host_id")), organization, version, protocol, scope, access.integer("grant_version", 1), role, expires)
        }
    }
}

class SessionDirectoryEntry private constructor(val id: String, val workspaceId: String?, val state: String, val lastPersisted: Long, val updatedAt: Long) {
    fun viewScope(grant: RuntimeDirectoryEntry): RelayScope? = try {
        if (!grant.canList() || grant.scope == null || "session.read" !in grant.scope.actions) null else {
            val actions = mutableSetOf("session.read")
            if ("command.status" in grant.scope.actions) {
                actions += "command.status"
                if (grant.role in setOf("operator", "owner")) {
                    if ("message.submit" in grant.scope.actions) actions += "message.submit"
                    if ("session.cancel" in grant.scope.actions) actions += "session.cancel"
                }
            }
            grant.scope.session(id, workspaceId, actions)
        }
    } catch (_: ProtocolException) { null }
    fun readScope(grant: RuntimeDirectoryEntry): RelayScope? = try {
        if (!grant.canList() || state == "unavailable") null else grant.scope?.readSession(id, workspaceId)
    } catch (_: ProtocolException) { null }
    companion object {
        fun parse(root: JsonObject): SessionDirectoryEntry {
            val workspace = when (val value = root.fields["workspace_id"]) { null, JsonNull -> null; is JsonString -> Contract.uuid(value.value); else -> throw ProtocolException() }
            val state = root.string("state")
            if (state !in setOf("available", "running", "archived", "unavailable")) throw ProtocolException()
            return SessionDirectoryEntry(Contract.uuid(root.string("session_id")), workspace, state, root.integer("last_persisted_seq", -1), relayTime(root.string("updated_at")))
        }
    }
}
