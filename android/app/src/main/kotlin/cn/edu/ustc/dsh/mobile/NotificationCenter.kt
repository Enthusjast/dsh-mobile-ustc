package cn.edu.ustc.dsh.mobile

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import cn.edu.ustc.dsh.auth.PushDeployment
import cn.edu.ustc.dsh.crypto.DeviceProofs
import cn.edu.ustc.dsh.network.LoginHttp
import cn.edu.ustc.dsh.protocol.*
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.util.UUID
import javax.inject.Inject
import javax.inject.Singleton

internal class PushRoute(val id: String, val owner: String, val deployment: String, val publicConfig: String, val origin: String, val organization: String,
    val project: String, val sender: String, val address: String, val secret: String, val active: Boolean, val expires: Long, val challenge: String?, val challengeExpiry: Long) {
    fun registration() = PushRegistration(id, organization, address, sha256(secret.toByteArray()))
    override fun toString() = "PushRoute"
}
internal class PushRevocation(val id: String, val origin: String, val secret: String) { override fun toString() = "PushRevocation" }
internal class PushNotice(val id: String, val expires: Long, val posted: Boolean)
internal class PushReceipt(val id: String, val state: String)
internal class PushRouting(val route: PushRoute?, val revocations: List<PushRevocation>, val notices: List<PushNotice>, val receipts: List<PushReceipt>, val clock: Long)

/** Local account fence for generic notifications. No credentials, signatures or actions live here. */
@Singleton
class NotificationCenter internal constructor(private val context: Context, private val slot: String) {
    @Inject constructor(@ApplicationContext context: Context) : this(context, "active")
    private val storage = PushStorage(context.applicationContext, slot)
    private val manager get() = context.getSystemService(NotificationManager::class.java)
    private val channel = "dsh-interactions-v1"
    private val tag = "dsh-interactions-$slot"
    internal fun snapshot(): PushRouting = synchronized(lock) { read() }
    fun allowed(): Boolean {
        if (Build.VERSION.SDK_INT >= 33 && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return false
        if (!manager.areNotificationsEnabled()) return false
        return manager.getNotificationChannel(channel)?.importance != NotificationManager.IMPORTANCE_NONE
    }
    internal fun ensureChannel() { manager.createNotificationChannel(NotificationChannel(channel, "远控交互提醒", NotificationManager.IMPORTANCE_HIGH).apply { description = "提醒中隐藏正文，打开后核对当前状态"; lockscreenVisibility = Notification.VISIBILITY_PRIVATE }) }
    internal fun stage(owner: String, deployment: String, config: PushDeployment, origin: String, organization: String, address: String): PushRoute = synchronized(lock) {
        val prior = read(); if (prior.route != null || prior.revocations.isNotEmpty()) throw IllegalStateException("push.cleanup_required")
        Contract.digest(owner); Contract.digest(deployment); Contract.uuid(organization)
        val route = PushRoute(UUID.randomUUID().toString(), owner, deployment, config.fingerprint, origin, organization, config.projectId, config.senderId, address,
            DeviceProofs.randomId(), false, System.currentTimeMillis() + 210_000, null, 0)
        route.registration(); write(PushRouting(route, emptyList(), emptyList(), emptyList(), System.currentTimeMillis())); route
    }
    internal fun matches(owner: String, id: String): Boolean = synchronized(lock) { read().route?.let { it.owner == owner && it.id == id } == true }
    internal fun update(owner: String, binding: PushBinding) = synchronized(lock) {
        val state = read(); val old = state.route ?: throw IllegalStateException("push.stale")
        if (old.owner != owner || old.id != binding.id) throw IllegalStateException("push.stale")
        if (binding.state !in setOf(PushBindingState.PENDING, PushBindingState.ACTIVE)) { retireLocked(state); return@synchronized }
        val active = binding.state == PushBindingState.ACTIVE
        val route = PushRoute(old.id, old.owner, old.deployment, old.publicConfig, old.origin, old.organization, old.project, old.sender, old.address, old.secret,
            active, if (active) binding.expiresAt else binding.challengeExpiresAt, old.challenge, old.challengeExpiry)
        write(PushRouting(route, state.revocations, state.notices, state.receipts, System.currentTimeMillis()))
        if (active) postLocked(read())
    }
    internal fun challenge(owner: String, id: String): PushPacket.Challenge? = synchronized(lock) {
        val route = read().route?.takeIf { it.owner == owner && it.id == id && !it.active } ?: return@synchronized null
        val nonce = route.challenge ?: return@synchronized null
        PushPacket.parse(mapOf("v" to "1", "kind" to "registration_challenge", "binding_id" to id, "challenge" to nonce, "expires_at" to Contract.timestamp(route.challengeExpiry))) as PushPacket.Challenge
    }
    /** Clear first, cancel OS state next. Old in-flight packets cannot post after this lock exits. */
    internal fun retire(owner: String? = null) = synchronized(lock) {
        try {
            val state = read()
            if (owner == null || state.route?.owner == owner) retireLocked(state)
        } catch (_: Exception) { storage.destroy(); manager.cancel(tag, 1) }
    }
    internal fun retirePending(owner: String) = synchronized(lock) { try { val state = read(); if (state.route?.owner == owner && !state.route.active) retireLocked(state) } catch (_: Exception) { storage.destroy(); manager.cancel(tag, 1) } }
    private fun retireLocked(state: PushRouting) {
        val route = state.route
        val revoked = if (route == null || state.revocations.any { it.id == route.id }) state.revocations else state.revocations + PushRevocation(route.id, route.origin, route.secret)
        if (revoked.size > 32) throw IllegalStateException("push.cleanup_required")
        write(PushRouting(null, revoked, emptyList(), emptyList(), System.currentTimeMillis()))
        manager.cancel(tag, 1)
        // System scheduling failure must not erase the persisted deletion capability.
        if (revoked.isNotEmpty() && slot == "active") runCatching { PushCleanupJob.schedule(context) }
    }
    internal suspend fun drain(http: LoginHttp): Boolean {
        val pending = synchronized(lock) { read().revocations.take(8) }
        for (entry in pending) {
            currentCoroutineContext().ensureActive()
            try { http.revokePush(entry.origin, entry.id, entry.secret) } catch (error: kotlinx.coroutines.CancellationException) { throw error } catch (_: Exception) { return false }
            synchronized(lock) {
                val state = read(); write(PushRouting(state.route, state.revocations.filterNot { it.id == entry.id && it.secret == entry.secret }, state.notices, state.receipts, state.clock))
            }
        }
        return synchronized(lock) { read().revocations.isEmpty() }
    }
    internal fun receiptDone(owner: String, receipt: PushReceipt) = synchronized(lock) {
        val state = read(); if (state.route?.owner != owner) return@synchronized
        write(PushRouting(state.route, state.revocations, state.notices, state.receipts.filterNot { it.id == receipt.id && it.state == receipt.state }, state.clock))
    }
    internal fun opened(owner: String, id: String) = synchronized(lock) {
        val state = read(); if (state.route?.owner != owner || state.notices.none { it.id == id }) return@synchronized
        write(PushRouting(state.route, state.revocations, state.notices, addReceipt(state.receipts, id, "opened"), state.clock)); manager.cancel(tag, 1)
    }
    internal fun reconcileDeployment(deployment: String?, publicConfig: String?) = synchronized(lock) {
        try { val state = read(); state.route?.let { if (it.deployment != deployment || it.publicConfig != publicConfig) retireLocked(state) } }
        catch (_: Exception) { storage.destroy(); manager.cancel(tag, 1) }
    }
    internal fun registeredAddress(config: PushDeployment, address: String) = synchronized(lock) {
        val state = read(); val route = state.route ?: return@synchronized
        if (route.publicConfig == config.fingerprint && route.address != address) retireLocked(state)
    }
    internal fun lostMessages(config: PushDeployment) = synchronized(lock) {
        val state = try { read() } catch (_: Exception) { return@synchronized }
        val route = state.route ?: return@synchronized
        if (!route.active || route.publicConfig != config.fingerprint || route.expires <= System.currentTimeMillis()) return@synchronized
        ensureChannel(); if (!allowed()) return@synchronized
        val pending = PendingIntent.getActivity(context, 0, NotificationOpen.intent(context, route.id, null), PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        manager.notify(tag, 1, Notification.Builder(context, channel).setSmallIcon(R.drawable.ic_dsh).setContentTitle("远控提醒可能有更新")
            .setContentText("打开后重新核对待处理交互").setVisibility(Notification.VISIBILITY_PRIVATE).setContentIntent(pending).setAutoCancel(true).setTimeoutAfter(600_000).build())
    }
    internal fun receive(config: PushDeployment, sender: String?, data: Map<String, String>) = synchronized(lock) {
        val packet = try { PushPacket.parse(data) } catch (_: Exception) { return@synchronized }
        val state = try { read() } catch (_: Exception) { manager.cancel(tag, 1); return@synchronized }
        val route = state.route ?: return@synchronized
        val now = System.currentTimeMillis()
        if (route.publicConfig != config.fingerprint || route.deployment != config.deploymentHash || sender != route.sender || packet.bindingId != route.id ||
            !packet.current(now) || now < state.clock || now >= route.expires) return@synchronized
        when (packet) {
            is PushPacket.Challenge -> {
                if (route.active) return@synchronized
                val updated = PushRoute(route.id, route.owner, route.deployment, route.publicConfig, route.origin, route.organization, route.project, route.sender, route.address,
                    route.secret, false, route.expires, packet.confirmation().string("challenge"), packet.expiresAt)
                write(PushRouting(updated, state.revocations, state.notices, state.receipts, now))
            }
            is PushPacket.Interaction -> {
                val notices = state.notices.filter { it.expires > now }
                if (notices.any { it.id == packet.id }) return@synchronized
                write(PushRouting(route, state.revocations, (notices + PushNotice(packet.id, packet.expiresAt, false)).takeLast(64), state.receipts, now))
                if (route.active) postLocked(read())
            }
        }
    }
    private fun postLocked(state: PushRouting) {
        val route = state.route ?: return
        val now = System.currentTimeMillis(); val notices = state.notices.filter { it.expires > now }
        if (!route.active || route.expires <= now || notices.none { !it.posted }) return
        ensureChannel()
        if (!allowed()) {
            var receipts = state.receipts
            notices.filterNot { it.posted }.forEach { receipts = addReceipt(receipts, it.id, "blocked") }
            write(PushRouting(route, state.revocations, notices, receipts, now)); return
        }
        val pending = NotificationOpen.intent(context, route.id, if (notices.size == 1) notices.single().id else null)
        val content = PendingIntent.getActivity(context, 0, pending, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val public = Notification.Builder(context, channel).setSmallIcon(R.drawable.ic_dsh).setContentTitle("远控交互提醒").setContentText("打开后核对当前状态").build()
        val notification = Notification.Builder(context, channel).setSmallIcon(R.drawable.ic_dsh).setContentTitle("远控有待核对的交互")
            .setContentText("参数和正文已隐藏，打开查看当前状态").setVisibility(Notification.VISIBILITY_PRIVATE).setPublicVersion(public)
            .setCategory(Notification.CATEGORY_REMINDER).setContentIntent(content).setAutoCancel(true).setTimeoutAfter(minOf(route.expires, notices.maxOf { it.expires }) - now).build()
        manager.notify(tag, 1, notification)
        var receipts = state.receipts
        notices.filterNot { it.posted }.forEach { receipts = addReceipt(receipts, it.id, "posted") }
        write(PushRouting(route, state.revocations, notices.map { PushNotice(it.id, it.expires, true) }, receipts, now))
    }
    private fun addReceipt(prior: List<PushReceipt>, id: String, state: String) = if (prior.any { it.id == id && it.state == state }) prior else (prior + PushReceipt(id, state)).takeLast(128)
    private fun read(): PushRouting {
        val root = storage.read() ?: return PushRouting(null, emptyList(), emptyList(), emptyList(), 0)
        root.exactKeys("v", "route", "revocations", "notices", "receipts", "clock"); root.integer("v", 1, 1)
        val route = if (root["route"] == JsonNull) null else root.obj("route").let { r ->
            r.exactKeys("id", "owner", "deployment", "public_config", "origin", "organization", "project", "sender", "address", "secret", "active", "expires", "challenge", "challenge_expiry")
            listOf("owner", "deployment", "public_config").forEach { Contract.digest(r.string(it)) }; Contract.uuid(r.string("id")); Contract.uuid(r.string("organization"))
            if (Contract.base64url(r.string("secret")).size != 32 || !Regex("[A-Za-z0-9_-]{22}").matches(r.string("address"))) throw ProtocolException()
            val nonce = when (val value = r["challenge"]) { JsonNull -> null; is JsonString -> value.value.also { if (Contract.base64url(it).size != 32) throw ProtocolException() }; else -> throw ProtocolException() }
            PushRoute(r.string("id"), r.string("owner"), r.string("deployment"), r.string("public_config"), r.string("origin"), r.string("organization"), r.string("project"), r.string("sender"), r.string("address"), r.string("secret"),
                (r["active"] as? JsonBoolean)?.value ?: throw ProtocolException(), r.integer("expires", 0), nonce, r.integer("challenge_expiry", 0))
        }
        val revocations = root.array("revocations").map { (it as? JsonObject ?: throw ProtocolException()).let { r -> r.exactKeys("id", "origin", "secret"); if (Contract.base64url(r.string("secret")).size != 32) throw ProtocolException(); PushRevocation(Contract.uuid(r.string("id")), r.string("origin"), r.string("secret")) } }
        val notices = root.array("notices").map { (it as? JsonObject ?: throw ProtocolException()).let { n -> n.exactKeys("id", "expires", "posted"); PushNotice(Contract.uuid(n.string("id")), n.integer("expires", 0), (n["posted"] as? JsonBoolean)?.value ?: throw ProtocolException()) } }
        val receipts = root.array("receipts").map { (it as? JsonObject ?: throw ProtocolException()).let { r -> r.exactKeys("id", "state"); if (r.string("state") !in setOf("posted", "opened", "blocked")) throw ProtocolException(); PushReceipt(Contract.uuid(r.string("id")), r.string("state")) } }
        if (revocations.size > 32 || notices.size > 64 || receipts.size > 128 || notices.map { it.id }.toSet().size != notices.size) throw ProtocolException()
        return PushRouting(route, revocations, notices, receipts, root.integer("clock", 0))
    }
    private fun write(state: PushRouting) {
        val route = state.route?.let { r -> jsonObject("id" to r.id.json(), "owner" to r.owner.json(), "deployment" to r.deployment.json(), "public_config" to r.publicConfig.json(), "origin" to r.origin.json(), "organization" to r.organization.json(), "project" to r.project.json(), "sender" to r.sender.json(), "address" to r.address.json(), "secret" to r.secret.json(), "active" to JsonBoolean(r.active), "expires" to r.expires.json(), "challenge" to (r.challenge?.json() ?: JsonNull), "challenge_expiry" to r.challengeExpiry.json()) } ?: JsonNull
        storage.write(jsonObject("v" to 1L.json(), "route" to route, "revocations" to JsonArray(state.revocations.map { jsonObject("id" to it.id.json(), "origin" to it.origin.json(), "secret" to it.secret.json()) }),
            "notices" to JsonArray(state.notices.map { jsonObject("id" to it.id.json(), "expires" to it.expires.json(), "posted" to JsonBoolean(it.posted)) }), "receipts" to JsonArray(state.receipts.map { jsonObject("id" to it.id.json(), "state" to it.state.json()) }), "clock" to state.clock.json()))
    }
    companion object { private val lock = Any() }
}

internal class NotificationOpen(val bindingId: String, val notificationId: String?) {
    companion object {
        private const val ACTION = "cn.edu.ustc.dsh.mobile.OPEN_NOTIFICATION"
        fun intent(context: Context, binding: String, id: String?) = Intent(context, MainActivity::class.java).setAction(ACTION).setData(Uri.parse("dsh-notification:/binding/$binding/entry/${id ?: "inbox"}"))
            .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        fun parse(intent: Intent?): NotificationOpen? { return try {
            val uri = intent?.data ?: return null
            if (intent.action != ACTION || uri.scheme != "dsh-notification" || uri.authority != null || uri.query != null || uri.fragment != null || uri.pathSegments.size != 4 || uri.pathSegments[0] != "binding" || uri.pathSegments[2] != "entry") null
            else NotificationOpen(Contract.uuid(uri.pathSegments[1]), uri.pathSegments[3].takeIf { it != "inbox" }?.let(Contract::uuid))
        } catch (_: Exception) { null } }
    }
}
