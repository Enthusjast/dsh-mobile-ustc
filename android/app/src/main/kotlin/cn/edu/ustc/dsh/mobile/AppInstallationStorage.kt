package cn.edu.ustc.dsh.mobile

import android.content.Context
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

internal enum class InstallStorageFailure { CONFLICT, CORRUPT, KEY_MISSING, UNAVAILABLE }
internal class InstallStorageException(val failure: InstallStorageFailure) : IllegalStateException("update storage: ${failure.name.lowercase()}")
internal data class StoredAppInstallation(val revision: Long, val record: AppInstallationRecord)

/** Blocking IO, using a separate app key. Contains correlation metadata, never school credentials. */
internal class AppInstallationStorage(context: Context, slot: String) {
    init { require(Regex("[a-z0-9-]{1,64}").matches(slot)) }
    private val directory = File(context.noBackupFilesDir, "app-installations/$slot")
    internal val file = AtomicFile(File(directory, "installation.json"))
    internal val alias = "dsh/app-installations/v1/$slot"
    private val binding = "dsh-app-installations-v1\u0000${context.packageName}\u0000$slot".toByteArray()
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    fun read(): StoredAppInstallation? = synchronized(lock) { checked { readLocked() } }
    fun save(record: AppInstallationRecord, expectedRevision: Long): StoredAppInstallation = synchronized(lock) {
        checked {
            val previous = readLocked()
            if ((previous?.revision ?: 0) != expectedRevision || expectedRevision !in 0 until MAX_SAFE_INTEGER) conflict()
            previous?.record?.let { old ->
                if (old.sameAttempt(record)) {
                    val permitted = try { old.transition(record.phase, record.updatedAt) } catch (_: ProtocolException) { conflict() }
                    if (permitted.document.sha256() != record.document.sha256()) conflict()
                } else if (!old.phase.terminal) conflict()
            }
            val revision = expectedRevision + 1
            val header = jsonObject("v" to 1L.json(), "revision" to revision.json())
            val plain = JsonDocument.of(jsonObject("domain" to DOMAIN.json(), "v" to 1L.json(), "revision" to revision.json(), "record" to record.document.root)).canonicalBytes()
            if (plain.size > MAX_CLEAR) corrupt()
            try {
                if (!keys.containsAlias(alias)) {
                    // Installation-result hints can arrive while locked after
                    // first unlock. This key carries no OAuth/proof/approval key.
                    val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false).build()
                    KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
                }
                val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()); updateAAD(aad(header)) }
                check(cipher.iv.size == 12)
                val encrypted = cipher.doFinal(plain)
                val bytes = JsonDocument.of(header.with("iv" to Contract.base64url(cipher.iv).json(), "ciphertext" to Contract.base64url(encrypted).json())).canonicalBytes()
                check(directory.isDirectory || directory.mkdirs())
                val output = file.startWrite()
                try {
                    output.write(bytes); output.fd.sync(); file.finishWrite(output)
                    val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
                    try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
                } catch (error: Exception) { file.failWrite(output); throw error }
                val saved = readLocked() ?: unavailable()
                if (saved.revision != revision || saved.record.document.sha256() != record.document.sha256()) unavailable()
                saved
            } finally { plain.fill(0) }
        }
    }
    /** Caller first retires/settles the original session; an in-flight attempt cannot be erased here. */
    fun erase(expectedRevision: Long) = synchronized(lock) {
        checked {
            val saved = readLocked()
            if ((saved?.revision ?: 0) != expectedRevision || saved?.record?.phase?.terminal == false) conflict()
            eraseLocked()
        }
    }
    /** Explicit recovery only, after the coordinator has cleaned this app's orphaned update sessions. */
    fun resetAfterSessionCleanup() = synchronized(lock) { checked { eraseLocked() } }
    private fun eraseLocked() {
        keys.deleteEntry(alias); file.delete()
        if (file.baseFile.exists() || File(file.baseFile.path + ".bak").exists() || File(file.baseFile.path + ".new").exists()) unavailable()
    }
    private fun readLocked(): StoredAppInstallation? {
        val raw = try {
            file.openRead().use { input ->
                val output = ByteArrayOutputStream(); val chunk = ByteArray(4096)
                while (true) {
                    val count = input.read(chunk)
                    if (count < 0) break
                    if (count == 0 || output.size() + count > 64 * 1024) corrupt()
                    output.write(chunk, 0, count)
                }
                output.toByteArray()
            }
        } catch (_: FileNotFoundException) {
            if (file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()) unavailable()
            return null
        }
        try {
            val root = JsonDocument.parse(raw).root; root.exactKeys("v", "revision", "iv", "ciphertext"); root.integer("v", 1, 1)
            val revision = root.integer("revision")
            val iv = Contract.base64url(root.string("iv")); val encrypted = Contract.base64url(root.string("ciphertext"))
            if (iv.size != 12 || encrypted.size !in 17..MAX_CLEAR + 16) corrupt()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)); updateAAD(aad(jsonObject("v" to 1L.json(), "revision" to revision.json()))) }
            val plain = cipher.doFinal(encrypted)
            try {
                val payload = JsonDocument.parse(plain).root; payload.exactKeys("domain", "v", "revision", "record"); payload.integer("v", 1, 1)
                if (payload.string("domain") != DOMAIN || payload.integer("revision") != revision) corrupt()
                return StoredAppInstallation(revision, AppInstallationRecord.parse(payload.obj("record")))
            } finally { plain.fill(0) }
        } finally { raw.fill(0) }
    }
    private fun aad(header: JsonObject) = binding + JsonDocument.of(header).canonicalBytes()
    private fun key(): SecretKey {
        val secret = keys.getKey(alias, null) as? SecretKey ?: throw InstallStorageException(InstallStorageFailure.KEY_MISSING)
        val info = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").getKeySpec(secret, KeyInfo::class.java) as KeyInfo
        if (secret.encoded != null || info.origin != KeyProperties.ORIGIN_GENERATED || info.keySize != 256 || info.isUserAuthenticationRequired ||
            info.purposes != (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) || info.blockModes.toSet() != setOf(KeyProperties.BLOCK_MODE_GCM) || info.encryptionPaddings.toSet() != setOf(KeyProperties.ENCRYPTION_PADDING_NONE)) corrupt()
        return secret
    }
    companion object {
        private val lock = Any()
        private const val DOMAIN = "dsh-mobile-ustc/app-installation-storage"
        private const val MAX_CLEAR = 32 * 1024
        private fun conflict(): Nothing = throw InstallStorageException(InstallStorageFailure.CONFLICT)
        private fun corrupt(): Nothing = throw InstallStorageException(InstallStorageFailure.CORRUPT)
        private fun unavailable(): Nothing = throw InstallStorageException(InstallStorageFailure.UNAVAILABLE)
        private fun <T> checked(action: () -> T): T = try { action() }
            catch (error: InstallStorageException) { throw error }
            catch (_: javax.crypto.AEADBadTagException) { corrupt() }
            catch (_: ProtocolException) { corrupt() }
            catch (_: Exception) { unavailable() }
    }
}
