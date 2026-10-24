package cn.edu.ustc.dsh.keystore

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import cn.edu.ustc.dsh.protocol.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

enum class VaultFailure { LOCK_REQUIRED, LOCKED, KEY_MISSING, CORRUPT, CONFLICT, UNAVAILABLE }
class VaultException(val failure: VaultFailure) : IllegalStateException("account vault: ${failure.name.lowercase()}")

class VaultEntry internal constructor(val accountId: String, val organizationId: String, val deploymentHash: String, val revision: Long, private val payload: ByteArray) : AutoCloseable {
    private var closed = false
    @Synchronized fun bytes(): ByteArray { check(!closed); return payload.copyOf() }
    @Synchronized override fun close() { payload.fill(0); closed = true }
}

/** One encrypted account slot. Public scope/deployment/revision metadata is authenticated as AAD. */
class AccountVault(context: Context, slot: String = "active") {
    companion object {
        const val MAX_CLEAR_BYTES = 96 * 1024 - 1024
        private val lock = Any()
    }
    init { require(Regex("[a-z0-9-]{1,64}").matches(slot)) }
    private val keyguard = context.applicationContext.getSystemService(KeyguardManager::class.java)
    private val directory = File(context.noBackupFilesDir, "account-vault/$slot")
    internal val file = AtomicFile(File(directory, "account.json"))
    internal val keyPrefix = "dsh/account-token/v1/$slot/"
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun read(): VaultEntry? = synchronized(lock) { vaultCheck { readLocked() } }

    fun save(accountId: String, organizationId: String, deploymentHash: String, plaintext: ByteArray, expectedRevision: Long): Long = synchronized(lock) {
        vaultCheck {
            unlocked()
            if (plaintext.size !in 1..MAX_CLEAR_BYTES) throw VaultException(VaultFailure.CORRUPT)
            val alias = alias(accountId, organizationId)
            var previousRevision = 0L
            readLocked()?.use { previous ->
                if (previous.accountId != accountId || previous.organizationId != organizationId || previous.deploymentHash != deploymentHash) throw VaultException(VaultFailure.CONFLICT)
                previousRevision = previous.revision
            }
            if (expectedRevision != previousRevision) throw VaultException(VaultFailure.CONFLICT)
            val revision = previousRevision + 1
            val header = header(accountId, organizationId, deploymentHash, revision)
            if (!keys.containsAlias(alias)) {
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false)
                // Android documents key-loss/unlock bugs on API 31–34. The
                // explicit secure/unlocked gate also applies on older devices.
                if (Build.VERSION.SDK_INT >= 35) spec.setUnlockedDeviceRequired(true)
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec.build()) }.generateKey()
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key(alias)); updateAAD(JsonDocument.of(header).canonicalBytes()) }
            val encrypted = cipher.doFinal(plaintext)
            check(cipher.iv.size == 12)
            val bytes = JsonDocument.of(header.with("iv" to Contract.base64url(cipher.iv).json(), "ciphertext" to Contract.base64url(encrypted).json())).canonicalBytes()
            check(directory.isDirectory || directory.mkdirs())
            val output = file.startWrite()
            try {
                output.write(bytes); output.fd.sync(); file.finishWrite(output)
                val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
                try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
            } catch (error: Exception) { file.failWrite(output); throw error }
            // Surface a failed platform rename/write before a caller sends a
            // rotating credential or declares a durable enrollment checkpoint.
            readLocked()?.use { check(it.revision == revision && it.bytes().contentEquals(plaintext)) } ?: throw VaultException(VaultFailure.UNAVAILABLE)
            revision
        }
    }

    /** Explicit local logout/reset only; server revocation and IdP logout are separate. */
    fun clear() = synchronized(lock) {
        vaultCheck {
            // Destroy decryptability first, even if a later filesystem removal fails.
            keys.aliases().toList().filter { it.startsWith(keyPrefix) }.forEach(keys::deleteEntry)
            file.delete()
            check(!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists() && !File(file.baseFile.path + ".new").exists())
        }
    }

    private fun readLocked(): VaultEntry? {
        val stream = try { file.openRead() } catch (_: FileNotFoundException) {
            if (file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()) throw VaultException(VaultFailure.UNAVAILABLE)
            return null
        }
        val bytes = stream.use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(8192)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (output.size() + count > JsonDocument.MAX_BYTES) throw VaultException(VaultFailure.CORRUPT)
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        unlocked()
        val root = JsonDocument.parse(bytes).root
        root.exactKeys("domain", "v", "account_id", "organization_id", "deployment_sha256", "revision", "iv", "ciphertext")
        if (root.string("domain") != "dsh-mobile-ustc/account-vault" || root.integer("v", 1, 1) != 1L) throw VaultException(VaultFailure.CORRUPT)
        val accountId = root.string("account_id"); val organizationId = root.string("organization_id"); val deployment = root.string("deployment_sha256")
        val revision = root.integer("revision", 1, 9_007_199_254_740_991)
        val header = header(accountId, organizationId, deployment, revision)
        val iv = Contract.base64url(root.string("iv")); val ciphertext = Contract.base64url(root.string("ciphertext"))
        if (iv.size != 12 || ciphertext.size !in 17..MAX_CLEAR_BYTES + 16) throw VaultException(VaultFailure.CORRUPT)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(alias(accountId, organizationId)), GCMParameterSpec(128, iv)); updateAAD(JsonDocument.of(header).canonicalBytes()) }
        return VaultEntry(accountId, organizationId, deployment, revision, cipher.doFinal(ciphertext))
    }

    private fun key(alias: String): SecretKey {
        val key = keys.getKey(alias, null) as? SecretKey ?: throw VaultException(VaultFailure.KEY_MISSING)
        val info = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (key.encoded != null || info.keySize != 256 || info.origin != KeyProperties.ORIGIN_GENERATED ||
            info.purposes != (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) || info.blockModes.toSet() != setOf(KeyProperties.BLOCK_MODE_GCM) ||
            info.encryptionPaddings.toSet() != setOf(KeyProperties.ENCRYPTION_PADDING_NONE) || info.isUserAuthenticationRequired) throw VaultException(VaultFailure.CORRUPT)
        return key
    }

    private fun unlocked() {
        if (!keyguard.isDeviceSecure) throw VaultException(VaultFailure.LOCK_REQUIRED)
        if (keyguard.isDeviceLocked) throw VaultException(VaultFailure.LOCKED)
    }
    private fun alias(accountId: String, organizationId: String): String = keyPrefix + DeviceKeyScope(accountId, organizationId).digest + "/1"
    private fun header(accountId: String, organizationId: String, deploymentHash: String, revision: Long): JsonObject {
        Contract.uuid(accountId); Contract.uuid(organizationId)
        if (!Regex("[0-9a-f]{64}").matches(deploymentHash) || revision !in 1..9_007_199_254_740_991) throw VaultException(VaultFailure.CORRUPT)
        return jsonObject("domain" to "dsh-mobile-ustc/account-vault".json(), "v" to 1L.json(), "account_id" to accountId.json(), "organization_id" to organizationId.json(), "deployment_sha256" to deploymentHash.json(), "revision" to revision.json())
    }
}

private inline fun <T> vaultCheck(block: () -> T): T = try { block() }
catch (error: VaultException) { throw error }
catch (_: javax.crypto.AEADBadTagException) { throw VaultException(VaultFailure.CORRUPT) }
catch (_: ProtocolException) { throw VaultException(VaultFailure.CORRUPT) }
catch (_: Exception) { throw VaultException(VaultFailure.UNAVAILABLE) }
