package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.ExportManifest
import cn.edu.ustc.dsh.protocol.JsonDocument
import java.io.*
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Private, disposable encrypted staging. Neither the ephemeral key nor a URI is persisted. */
class EncryptedExportStage(directory: File, private val manifest: ExportManifest) : AutoCloseable {
    internal val file: File
    private val closed = AtomicBoolean()
    private val reading = AtomicReference<InputStream?>()
    private val key = ByteArray(32).also(SecureRandom()::nextBytes)
    private val prefix = ByteArray(8).also(SecureRandom()::nextBytes)
    private val binding = MessageDigest.getInstance("SHA-256").digest(JsonDocument.of(manifest.json()).canonicalBytes())
    private var writer: StagingOutput? = null
    private var opened = false
    init {
        if (!directory.isDirectory && !directory.mkdirs()) throw RemoteRequestException("file.storage_unavailable")
        file = File.createTempFile("export-", ".encrypted", directory)
    }
    @Synchronized fun output(): OutputStream {
        if (closed.get() || opened) throw RemoteRequestException("file.state_changed")
        opened = true
        return StagingOutput().also { writer = it }
    }
    private fun cipher(mode: Int, index: Int, size: Int): Cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
        val iv = ByteBuffer.allocate(12).put(prefix).putInt(index).array()
        init(mode, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        updateAAD(binding); updateAAD(ByteBuffer.allocate(8).putInt(index).putInt(size).array())
    }
    private inner class StagingOutput : OutputStream() {
        private val target = DataOutputStream(BufferedOutputStream(FileOutputStream(file)))
        private val buffer = ByteArray(CHUNK)
        private var fill = 0
        private var count = 0L
        private var index = 0
        var finished = false; private set
        private fun emit() {
            if (fill == 0) return
            val encrypted = cipher(Cipher.ENCRYPT_MODE, index++, fill).doFinal(buffer, 0, fill)
            target.writeInt(fill); target.write(encrypted); buffer.fill(0, 0, fill); fill = 0
        }
        override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
        @Synchronized override fun write(bytes: ByteArray, offset: Int, length: Int) {
            if (closed.get() || finished || length < 0 || offset < 0 || offset > bytes.size - length || count + length > manifest.sizeBytes) throw IOException("file staging interrupted")
            var position = offset; var remaining = length
            while (remaining > 0) {
                val size = minOf(CHUNK - fill, remaining)
                bytes.copyInto(buffer, fill, position, position + size); fill += size; position += size; remaining -= size; count += size
                if (fill == CHUNK) emit()
            }
        }
        @Synchronized override fun close() {
            if (finished) return
            try { emit() } finally { finished = true; buffer.fill(0); target.close() }
        }
    }
    /** GCM verifies each bounded chunk; final length/digest verification precedes caller success. */
    fun copyVerified(destination: OutputStream, current: () -> Unit = {}, progress: (Long) -> Unit = {}) {
        if (closed.get() || writer?.finished != true) throw RemoteRequestException("file.state_changed")
        val raw = FileInputStream(file)
        if (!reading.compareAndSet(null, raw)) { raw.close(); throw RemoteRequestException("file.state_changed") }
        try {
            DataInputStream(BufferedInputStream(raw)).use { source ->
                val hash = MessageDigest.getInstance("SHA-256")
                var count = 0L; var index = 0
                while (count < manifest.sizeBytes) {
                    current(); if (closed.get()) throw RemoteRequestException("file.state_changed")
                    val size = source.readInt()
                    if (size !in 1..CHUNK || size.toLong() != minOf(CHUNK.toLong(), manifest.sizeBytes - count)) throw RemoteRequestException("file.integrity_mismatch")
                    val encrypted = ByteArray(size + 16); source.readFully(encrypted)
                    val bytes = cipher(Cipher.DECRYPT_MODE, index++, size).doFinal(encrypted)
                    try { current(); hash.update(bytes); destination.write(bytes); count += bytes.size; progress(count) } finally { bytes.fill(0) }
                }
                current()
                val digest = hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) }
                if (source.read() != -1 || count != manifest.sizeBytes || digest != manifest.sha256) throw RemoteRequestException("file.integrity_mismatch")
            }
        } catch (error: java.util.concurrent.CancellationException) { throw error }
        catch (error: Exception) {
            throw if (error is RemoteRequestException) error else RemoteRequestException("file.integrity_mismatch")
        } finally { reading.compareAndSet(raw, null) }
    }
    @Synchronized override fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { reading.getAndSet(null)?.close() }; runCatching { writer?.close() }
        key.fill(0); prefix.fill(0); binding.fill(0); file.delete()
    }
    override fun toString() = "EncryptedExportStage"
    companion object { private const val CHUNK = 64 * 1024 }
}
