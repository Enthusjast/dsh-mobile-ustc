package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.util.AtomicFile
import cn.edu.ustc.dsh.protocol.*
import java.io.File
import java.io.FileNotFoundException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Background routing/deletion metadata only. Never an OAuth token, proof key or interaction body. */
internal class PushStorage(context: Context, slot: String) {
    private val directory = File(context.noBackupFilesDir, "notification-routing/$slot")
    private val file = AtomicFile(File(directory, "routing.json"))
    private val alias = "dsh/notification-routing/v1/$slot"
    private val aad = "dsh-notification-routing-v1\u0000$slot".toByteArray()
    private val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    init { require(Regex("[a-z0-9-]{1,64}").matches(slot)) }
    fun read(): JsonObject? = checked {
        val bytes = try { file.openRead().use { it.readBytesBounded(96 * 1024) } } catch (_: FileNotFoundException) { if (file.baseFile.exists() || File(file.baseFile.path + ".bak").exists()) throw IllegalStateException(); return@checked null }
        try {
            val root = JsonDocument.parse(bytes).root; root.exactKeys("v", "iv", "ciphertext"); root.integer("v", 1, 1)
            val iv = Contract.base64url(root.string("iv")); if (iv.size != 12) throw ProtocolException()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)); updateAAD(aad) }
            val plain = cipher.doFinal(Contract.base64url(root.string("ciphertext")))
            try { JsonDocument.parse(plain).root } finally { plain.fill(0) }
        } finally { bytes.fill(0) }
    }
    fun write(root: JsonObject) = checked {
        val plain = JsonDocument.of(root).canonicalBytes()
        if (plain.size > 64 * 1024) throw ProtocolException()
        try {
            if (!keys.containsAlias(alias)) {
                // This key intentionally remains usable after first unlock while
                // locked: it protects only generic routing and deletion capabilities.
                val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false).build()
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()); updateAAD(aad) }
            val encrypted = cipher.doFinal(plain)
            val data = JsonDocument.of(jsonObject("v" to 1L.json(), "iv" to Contract.base64url(cipher.iv).json(), "ciphertext" to Contract.base64url(encrypted).json())).canonicalBytes()
            check(directory.isDirectory || directory.mkdirs())
            val output = file.startWrite()
            try { output.write(data); output.fd.sync(); file.finishWrite(output); val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0); try { Os.fsync(fd) } finally { Os.close(fd) } }
            catch (error: Exception) { file.failWrite(output); throw error }
            // Surface an unsuccessful atomic platform write before enrolling or posting.
            check(read()?.let { JsonDocument.of(it).canonicalBytes().contentEquals(plain) } == true)
        } finally { plain.fill(0) }
    }
    fun destroy() { runCatching { keys.deleteEntry(alias) }; file.delete() }
    private fun key() = keys.getKey(alias, null) as? SecretKey ?: throw IllegalStateException("push.storage_unavailable")
    private fun <T> checked(action: () -> T): T = try { action() } catch (_: Exception) { throw IllegalStateException("push.storage_unavailable") }
}

private fun java.io.InputStream.readBytesBounded(limit: Int): ByteArray {
    val buffer = java.io.ByteArrayOutputStream(); val chunk = ByteArray(4096)
    while (true) { val count = read(chunk); if (count < 0) break; if (count == 0 || buffer.size() + count > limit) throw ProtocolException(); buffer.write(chunk, 0, count) }
    return buffer.toByteArray()
}
