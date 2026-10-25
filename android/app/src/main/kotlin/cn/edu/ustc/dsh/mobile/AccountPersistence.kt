package cn.edu.ustc.dsh.mobile

import android.annotation.SuppressLint
import android.content.Context
import cn.edu.ustc.dsh.auth.*
import cn.edu.ustc.dsh.data.SqlCommandJournal
import cn.edu.ustc.dsh.command.CommandOwner
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.protocol.Contract
import cn.edu.ustc.dsh.protocol.RelayScope
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal data class ScopeReference(val account: String, val organization: String) {
    val encoded: String get() = "$account|$organization"
    fun scope() = DeviceKeyScope(account, organization)
}

/** Public cleanup references only. A verified encrypted account protects its exact scope during recovery. */
internal class PendingKeyLedger(private val context: Context, private val name: String) {
    private fun preferences() = context.getSharedPreferences(name, Context.MODE_PRIVATE)
    private fun entries() = preferences().getStringSet("scopes", emptySet())!!.toMutableSet().also { check(it.size <= 16) }
    @SuppressLint("UseKtx")
    fun add(reference: ScopeReference) {
        val values = entries(); check(values.size < 16 || reference.encoded in values)
        values += reference.encoded
        check(preferences().edit().putStringSet("scopes", values).commit())
    }
    @SuppressLint("UseKtx")
    fun delete(reference: ScopeReference) {
        SqlCommandJournal.eraseAccount(context, reference.account, reference.organization)
        DeviceKeyStore(context).use { owner -> DeviceKeyPurpose.entries.forEach { owner.delete(reference.scope(), it, 1) } }
        val values = entries(); values -= reference.encoded
        check(preferences().edit().putStringSet("scopes", values).commit())
    }
    fun recover(protected: ScopeReference? = null) {
        entries().forEach { value ->
            val parts = value.split('|'); check(parts.size == 2)
            val reference = ScopeReference(Contract.uuid(parts[0]), Contract.uuid(parts[1]))
            if (reference != protected) delete(reference)
        }
    }
}

internal class OpenAccount(val checkpoint: AccountCheckpoint?, val reference: ScopeReference, val owner: DeviceKeyStore, val proof: DeviceKeyHandle, val approval: DeviceKeyHandle?) : AutoCloseable {
    override fun close() = owner.close()
}

/** All disk mutations and cleanup share a lock and check the calling account generation inside it. */
internal class AccountPersistence(private val context: Context, slot: String, preferencesName: String, private val current: (Long) -> Boolean) {
    private val mutex = Mutex()
    private val vault = AccountVault(context, slot)
    private val ledger = PendingKeyLedger(context, preferencesName)
    private var revision = 0L

    private suspend fun <T> transaction(stamp: Long, action: () -> T): T = withContext(NonCancellable + Dispatchers.IO) {
        mutex.withLock { if (!current(stamp)) throw CancellationException(); action() }
    }

    suspend fun load(config: LoginConfiguration, stamp: Long, now: Long): OpenAccount? = transaction(stamp) {
        val opened = vault.read()
        if (opened == null) {
            revision = 0
            ledger.recover()
            return@transaction null
        }
        opened.use { entry ->
            if (entry.organizationId != config.organizationId || entry.deploymentHash != config.fingerprint) throw LoginException(LoginFailure.CONFIGURATION)
            val reference = ScopeReference(entry.accountId, entry.organizationId)
            val owner = DeviceKeyStore(context)
            try {
                val proof = owner.load(reference.scope(), DeviceKeyPurpose.PROOF, 1)
                val clear = entry.bytes()
                val checkpoint = try { AccountCheckpoint.parseAuthenticated(clear, config, proof.thumbprint, now, entry.accountId) } finally { clear.fill(0) }
                val approval = checkpoint.approvalKeyJkt?.let { expected ->
                    owner.load(reference.scope(), DeviceKeyPurpose.APPROVAL, 1).also { if (it.thumbprint != expected) throw LoginException(LoginFailure.IDENTITY) }
                }
                ledger.recover(reference); ledger.add(reference)
                revision = entry.revision
                OpenAccount(checkpoint, reference, owner, proof, approval)
            } catch (error: Exception) { owner.close(); throw error }
        }
    }

    suspend fun createProof(reference: ScopeReference, stamp: Long): OpenAccount = transaction(stamp) {
        ledger.add(reference)
        val owner = DeviceKeyStore(context)
        try { OpenAccount(null, reference, owner, owner.create(reference.scope(), DeviceKeyPurpose.PROOF, 1), null) }
        catch (error: Exception) { owner.close(); throw error }
    }

    suspend fun approval(owner: DeviceKeyStore, reference: ScopeReference, stamp: Long): DeviceKeyHandle = transaction(stamp) {
        try { owner.load(reference.scope(), DeviceKeyPurpose.APPROVAL, 1) }
        catch (error: DeviceCryptoException) {
            if (error.failure != DeviceCryptoFailure.KEY_MISSING) throw error
            owner.create(reference.scope(), DeviceKeyPurpose.APPROVAL, 1)
        }
    }

    suspend fun save(checkpoint: AccountCheckpoint, stamp: Long) = transaction(stamp) {
        val clear = checkpoint.authenticatedStorageBytes()
        try { revision = vault.save(checkpoint.accountId, checkpoint.organizationId, checkpoint.session.deploymentFingerprint, clear, revision) }
        finally { clear.fill(0) }
    }
    suspend fun commands(owner: CommandOwner, stamp: Long): SqlCommandJournal = transaction(stamp) {
        SqlCommandJournal.open(context, owner)
    }
    suspend fun revokeCommands(owner: CommandOwner, runtime: String, stamp: Long) = transaction(stamp) {
        SqlCommandJournal.open(context, owner).use { journal -> runBlocking { journal.revokeRuntime(runtime) } }
    }
    suspend fun retainHistory(owner: CommandOwner, scopes: Map<String, RelayScope>, stamp: Long) = transaction(stamp) {
        SqlCommandJournal.open(context, owner).use { journal -> runBlocking { journal.retainTranscripts(scopes) } }
    }

    suspend fun clear(stamp: Long, extra: ScopeReference?) = transaction(stamp) {
        vault.clear()
        if (extra != null) ledger.delete(extra)
        ledger.recover()
        revision = 0
    }
}
