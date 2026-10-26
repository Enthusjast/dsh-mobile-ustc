package cn.edu.ustc.dsh.protocol

/** Transport references only. No push payload carries an action or trusted context. */
sealed class PushPacket(val bindingId: String, val expiresAt: Long) {
    class Challenge internal constructor(binding: String, expiry: Long, internal val nonce: String) : PushPacket(binding, expiry) {
        fun confirmation() = jsonObject("challenge" to nonce.json())
        override fun toString() = "PushChallenge"
    }
    class Interaction internal constructor(binding: String, expiry: Long, val id: String) : PushPacket(binding, expiry) { override fun toString() = "PushInteraction" }
    fun current(now: Long = System.currentTimeMillis()) = expiresAt > now && expiresAt - now <= 600_000
    companion object {
        fun parse(data: Map<String, String>): PushPacket {
            if (data.size != 5 || data.entries.sumOf { it.key.toByteArray().size + it.value.toByteArray().size } > 2048 || data["v"] != "1") throw ProtocolException()
            val root = JsonObject(data.mapValues { it.value.json() })
            val binding = Contract.uuid(root.string("binding_id")); val expires = relayTime(root.string("expires_at"))
            return when (root.string("kind")) {
                "registration_challenge" -> {
                    root.exactKeys("v", "kind", "binding_id", "expires_at", "challenge")
                    val nonce = root.string("challenge"); if (Contract.base64url(nonce).size != 32) throw ProtocolException()
                    Challenge(binding, expires, nonce)
                }
                "interaction" -> { root.exactKeys("v", "kind", "binding_id", "expires_at", "notification_id"); Interaction(binding, expires, Contract.uuid(root.string("notification_id"))) }
                else -> throw ProtocolException()
            }
        }
    }
}

class PushRegistration(val bindingId: String, val organizationId: String, val address: String, val revokeHash: String) {
    init { Contract.uuid(bindingId); Contract.uuid(organizationId); Contract.digest(revokeHash); if (!Regex("[A-Za-z0-9_-]{22}").matches(address)) throw ProtocolException() }
    fun json() = jsonObject("binding_id" to bindingId.json(), "organization_id" to organizationId.json(), "provider" to "fcm".json(), "address" to address.json(), "revoke_secret_sha256" to revokeHash.json())
    override fun toString() = "PushRegistration"
}
enum class PushBindingState { PENDING, ACTIVE, DISABLED, EXPIRED }
class PushBinding private constructor(val id: String, val state: PushBindingState, val challengeExpiresAt: Long, val expiresAt: Long) {
    override fun toString() = "PushBinding($state)"
    companion object {
        fun parse(root: JsonObject): PushBinding {
            root.exactKeys("binding_id", "state", "challenge_expires_at", "expires_at")
            val state = when (root.string("state")) { "pending" -> PushBindingState.PENDING; "active" -> PushBindingState.ACTIVE; "disabled" -> PushBindingState.DISABLED; "expired" -> PushBindingState.EXPIRED; else -> throw ProtocolException() }
            val challenge = relayTime(root.string("challenge_expires_at")); val expiry = relayTime(root.string("expires_at"))
            if (expiry < challenge || expiry - System.currentTimeMillis() > 604_830_000) throw ProtocolException()
            return PushBinding(Contract.uuid(root.string("binding_id")), state, challenge, expiry)
        }
    }
}
class PushCapabilities private constructor(val project: String?, val packageName: String?, val sources: Set<String>) {
    companion object {
        fun parse(root: JsonObject): PushCapabilities {
            root.exactKeys("v", "providers", "sources", "verification", "lease_seconds"); root.integer("v", 1, 1)
            if (root.string("verification") != "provider_challenge" || root.integer("lease_seconds", 604800, 604800) != 604800L) throw ProtocolException()
            val providers = root.array("providers"); if (providers.size > 1) throw ProtocolException()
            val provider = providers.singleOrNull()?.let { it as? JsonObject ?: throw ProtocolException() }
            provider?.let {
                it.exactKeys("provider", "project_id", "package_name", "address_kind")
                if (it.string("provider") != "fcm" || it.string("address_kind") != "fid") throw ProtocolException()
                if (!Regex("([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})").matches(it.string("project_id")) || !Regex("[a-zA-Z][a-zA-Z0-9_]*(\\.[a-zA-Z][a-zA-Z0-9_]*)+").matches(it.string("package_name"))) throw ProtocolException()
            }
            val sources = root.array("sources").map { (it as? JsonString)?.value ?: throw ProtocolException() }
            if (sources.toSet().size != sources.size || sources.any { it !in setOf("approval", "question", "timed_question") }) throw ProtocolException()
            return PushCapabilities(provider?.string("project_id"), provider?.string("package_name"), sources.toSet())
        }
    }
}
class NotificationReference private constructor(val id: String, val bindingId: String, val kind: String, val referenceId: String, val runtimeId: String, val epoch: String,
    val sessionId: String, val state: String, val availability: String, val expiresAt: Long) {
    fun actionable() = (state == "pending" || kind == "timed_question" && state == "continued") && availability == "online" && expiresAt > System.currentTimeMillis()
    override fun toString() = "NotificationReference"
    companion object {
        fun parse(root: JsonObject): NotificationReference {
            root.exactKeys("notification_id", "binding_id", "kind", "reference_id", "runtime_id", "runtime_epoch", "session_id", "state", "availability", "expires_at")
            val states = when (root.string("kind")) {
                "approval" -> setOf("pending", "decision_received", "allowed", "denied", "expired", "cancelled", "invalidated", "outcome_unknown")
                "question" -> setOf("pending", "expired", "ended")
                "timed_question" -> setOf("pending", "continued", "reply_queued", "ended")
                else -> throw ProtocolException()
            }
            if (root.string("availability") !in setOf("online", "host_offline", "stale_epoch", "ended", "state_unavailable") || root.string("state") !in states) throw ProtocolException()
            return NotificationReference(Contract.uuid(root.string("notification_id")), Contract.uuid(root.string("binding_id")), root.string("kind"), Contract.uuid(root.string("reference_id")),
                Contract.uuid(root.string("runtime_id")), Contract.uuid(root.string("runtime_epoch")), Contract.uuid(root.string("session_id")), root.string("state"), root.string("availability"), relayTime(root.string("expires_at")))
        }
    }
}
class NotificationPage private constructor(val items: List<NotificationReference>, val cursor: String?) {
    companion object {
        fun parse(root: JsonObject): NotificationPage {
            root.exactKeys("items", "cursor"); val items = root.array("items"); if (items.size > 64) throw ProtocolException()
            val parsed = items.map { NotificationReference.parse(it as? JsonObject ?: throw ProtocolException()) }
            if (parsed.map { it.id }.toSet().size != parsed.size) throw ProtocolException()
            val cursor = when (val value = root["cursor"]) { JsonNull -> null; is JsonString -> Contract.uuid(value.value); else -> throw ProtocolException() }
            return NotificationPage(parsed, cursor)
        }
    }
}
