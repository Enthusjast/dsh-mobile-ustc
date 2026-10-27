package cn.edu.ustc.dsh.data

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.*
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import cn.edu.ustc.dsh.command.*
import cn.edu.ustc.dsh.protocol.*
import java.io.File
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.*
import javax.crypto.spec.GCMParameterSpec

/** Separate purpose/alias from account tokens, proof keys and approval keys. */
internal class DatabaseKeyVault(private val context: Context, private val owner: CommandOwner, private val directory: File) {
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val alias = "dsh/local-db/v1/${owner.scopeHash}/${owner.fingerprint}"
    private val file = AtomicFile(File(directory, "key.json"))
    private val header = jsonObject("domain" to "dsh-mobile-ustc/local-db-key".json(), "v" to 1L.json(), "owner" to owner.root)
    fun unlocked() {
        val guard = context.getSystemService(KeyguardManager::class.java)
        if (!guard.isDeviceSecure) throw CommandDataException("data.lock_required")
        if (guard.isDeviceLocked) throw CommandDataException("data.locked")
    }
    fun open(databaseExists: Boolean): ByteArray = checked {
        unlocked()
        if (file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()) return@checked read()
        if (databaseExists) throw CommandDataException("data.key_missing")
        check(directory.isDirectory || directory.mkdirs())
        if (!keys.containsAlias(alias)) {
            val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false)
            // Match the existing token vault's explicit unlocked gate and API 31–34 workaround.
            if (Build.VERSION.SDK_INT >= 35) spec.setUnlockedDeviceRequired(true)
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec.build()) }.generateKey()
        }
        val passphrase = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, wrappingKey()); updateAAD(JsonDocument.of(header).canonicalBytes()) }
            val bytes = JsonDocument.of(header.with("iv" to Contract.base64url(cipher.iv).json(), "ciphertext" to Contract.base64url(cipher.doFinal(passphrase)).json())).canonicalBytes()
            val output = file.startWrite()
            try {
                output.write(bytes); output.fd.sync(); file.finishWrite(output)
                val descriptor = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
                try { Os.fsync(descriptor) } finally { Os.close(descriptor) }
            } catch (error: Exception) { file.failWrite(output); throw error }
            val verified = read()
            if (!verified.contentEquals(passphrase)) { verified.fill(0); throw CommandDataException("data.key_corrupt") }
            verified
        } finally { passphrase.fill(0) }
    }
    private fun read(): ByteArray {
        val bytes = file.openRead().use { input ->
            val output = ByteArrayOutputStream()
            val buffer = ByteArray(1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (output.size() + count > 4096) throw CommandDataException("data.key_corrupt")
                output.write(buffer, 0, count)
            }
            output.toByteArray()
        }
        if (bytes.size > 4096) throw CommandDataException("data.key_corrupt")
        val root = JsonDocument.parse(bytes).root
        root.exactKeys("domain", "v", "owner", "iv", "ciphertext")
        val supplied = jsonObject("domain" to root["domain"], "v" to root["v"], "owner" to root["owner"])
        if (JsonDocument.of(supplied).canonicalText() != JsonDocument.of(header).canonicalText()) throw CommandDataException("data.owner_mismatch")
        val iv = Contract.base64url(root.string("iv")); val encrypted = Contract.base64url(root.string("ciphertext"))
        if (iv.size != 12 || encrypted.size != 48) throw CommandDataException("data.key_corrupt")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, wrappingKey(), GCMParameterSpec(128, iv)); updateAAD(JsonDocument.of(header).canonicalBytes()) }
        return cipher.doFinal(encrypted).also { if (it.size != 32) throw CommandDataException("data.key_corrupt") }
    }
    private fun wrappingKey(): SecretKey {
        val key = keys.getKey(alias, null) as? SecretKey ?: throw CommandDataException("data.key_missing")
        val info = SecretKeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        if (key.encoded != null || info.keySize != 256 || info.origin != KeyProperties.ORIGIN_GENERATED || info.isUserAuthenticationRequired ||
            info.purposes != (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) || info.blockModes.toSet() != setOf(KeyProperties.BLOCK_MODE_GCM) ||
            info.encryptionPaddings.toSet() != setOf(KeyProperties.ENCRYPTION_PADDING_NONE)) throw CommandDataException("data.key_corrupt")
        return key
    }
    companion object {
        fun eraseScope(account: String, organization: String) {
            val prefix = "dsh/local-db/v1/${CommandOwner.scopeHash(account, organization)}/"
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.let { keys -> keys.aliases().toList().filter { it.startsWith(prefix) }.forEach(keys::deleteEntry) }
        }
    }
}

internal inline fun <T> checked(action: () -> T): T = try { action() }
catch (error: kotlinx.coroutines.CancellationException) { throw error }
catch (error: CommandDataException) { throw error }
catch (error: Exception) { throw CommandDataException("data.unavailable").also { it.initCause(error) } }
