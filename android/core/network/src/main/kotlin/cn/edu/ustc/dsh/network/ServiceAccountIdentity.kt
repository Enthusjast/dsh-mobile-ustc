package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*

/** A current authenticated control-plane mapping, never derived from an OIDC subject or deployment UUID. */
class ServiceAccountIdentity private constructor(val userId: String, val memberships: Map<String, String>) {
    companion object {
        internal fun parse(root: JsonObject, issuer: String, subject: String, clientId: String, scopes: Set<String>, organizationId: String): ServiceAccountIdentity {
            try {
                root.exactKeys("issuer", "subject", "client_id", "scopes", "user_id", "memberships")
                if (root.string("issuer") != issuer || root.string("subject") != subject || root.string("client_id") != clientId) throw RemoteRequestException("auth.identity_mismatch")
                val returnedScopes = root.array("scopes").map { Contract.boundedText((it as? JsonString)?.value ?: throw RemoteRequestException("network.invalid_response"), 128) }
                if (returnedScopes.size > 64 || returnedScopes.toSet().size != returnedScopes.size || returnedScopes.toSet() != scopes) throw RemoteRequestException("auth.identity_mismatch")
                val userId = Contract.uuid(root.string("user_id"))
                val entries = root.array("memberships")
                if (entries.size > 256) throw RemoteRequestException("network.invalid_response")
                val memberships = linkedMapOf<String, String>()
                entries.forEach { value ->
                    val membership = value as? JsonObject ?: throw RemoteRequestException("network.invalid_response")
                    membership.exactKeys("organization_id", "role")
                    val id = Contract.uuid(membership.string("organization_id"))
                    val role = membership.string("role")
                    if (role !in setOf("member", "admin") || memberships.put(id, role) != null) throw RemoteRequestException("network.invalid_response")
                }
                if (organizationId !in memberships) throw RemoteRequestException("access.organization_missing")
                return ServiceAccountIdentity(userId, java.util.Collections.unmodifiableMap(memberships))
            } catch (error: RemoteRequestException) { throw error }
            catch (_: Exception) { throw RemoteRequestException("network.invalid_response") }
        }
    }
}
