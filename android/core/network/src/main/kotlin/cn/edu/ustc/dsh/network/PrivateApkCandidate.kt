package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.AppRelease
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardOpenOption.READ
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean

/** Disposable storage beneath an application-private directory. No public URI or persisted trust marker. */
class PrivateApkCandidate(directory: File, val release: AppRelease) : AutoCloseable {
    internal val file: File
    private val closed = AtomicBoolean()
    private var sealed = false
    @Volatile private var writer: CandidateOutput? = null
    init {
        var created: File? = null
        try {
            if (Files.isSymbolicLink(directory.toPath()) || !directory.isDirectory && !directory.mkdirs() || directory.usableSpace < release.sizeBytes + 1024 * 1024) unavailable()
            file = File.createTempFile("candidate-", ".apk", directory)
            created = file
            if (!file.setReadable(false, false) || !file.setWritable(false, false) || !file.setReadable(true, true) || !file.setWritable(true, true)) {
                file.delete(); unavailable()
            }
        } catch (error: RemoteRequestException) { created?.delete(); throw error }
        catch (_: Exception) { created?.delete(); unavailable() }
    }
    @Synchronized fun output(): OutputStream {
        current()
        if (writer != null || sealed) changed()
        return CandidateOutput().also {
            writer = it
            if (closed.get()) { it.close(); file.delete(); changed() }
        }
    }
    /** Close the writer before sealing; hash the actual file independently of the network stream. */
    @Synchronized fun seal(current: () -> Unit = {}) {
        this.current(); current()
        if (sealed || writer?.finished != true) changed()
        try {
            verifyBytes(current)
            if (!file.setWritable(false, false)) unavailable()
            sealed = true
        } catch (error: Exception) { close(); throw error }
    }
    /** Checks length/SHA-256, not APK signatures. The platform callback runs between two byte checks. */
    @Synchronized fun <T> inspectVerified(current: () -> Unit = {}, inspect: (File) -> T): T {
        this.current(); current()
        if (!sealed) changed()
        try {
            val before = verifyBytes(current)
            val result = inspect(file)
            current()
            val after = verifyBytes(current)
            if (before.fileKey() != after.fileKey()) changed()
            return result
        } catch (error: Exception) { close(); throw error }
    }
    /** Requires a fresh platform verdict first. A receiving installer session must be abandoned on copy failure. */
    @Synchronized fun copyVerifiedTo(destination: OutputStream, current: () -> Unit = {}) {
        inspectVerified(current) { hashFile(current, destination) }
    }
    private fun attributes(): BasicFileAttributes {
        current()
        val result = try { Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, NOFOLLOW_LINKS) }
            catch (_: Exception) { throw RemoteRequestException("update.storage_unavailable") }
        if (!result.isRegularFile || result.size() != release.sizeBytes) integrity()
        return result
    }
    private fun verifyBytes(current: () -> Unit): BasicFileAttributes {
        val before = attributes()
        hashFile(current)
        val after = attributes()
        if (before.fileKey() != after.fileKey()) changed()
        return after
    }
    private fun hashFile(current: () -> Unit, destination: OutputStream? = null) {
        val hash = MessageDigest.getInstance("SHA-256")
        var count = 0L
        try {
            Files.newInputStream(file.toPath(), READ, NOFOLLOW_LINKS).use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    this.current(); current()
                    val size = input.read(buffer)
                    if (size < 0) break
                    if (size == 0 || count + size > release.sizeBytes) integrity()
                    hash.update(buffer, 0, size); destination?.write(buffer, 0, size); count += size
                }
            }
        } catch (error: java.util.concurrent.CancellationException) { throw error }
        catch (error: RemoteRequestException) { throw error }
        catch (_: Exception) { unavailable() }
        this.current(); current()
        if (count != release.sizeBytes || hash.digest().joinToString("") { "%02x".format(it.toInt() and 255) } != release.sha256) integrity()
    }
    private inner class CandidateOutput : OutputStream() {
        private val target = FileOutputStream(file)
        init { if (closed.get()) { runCatching { target.close() }; file.delete(); changed() } }
        private var count = 0L
        @Volatile var finished = false; private set
        override fun write(value: Int) = write(byteArrayOf(value.toByte()), 0, 1)
        override fun write(bytes: ByteArray, offset: Int, length: Int) = synchronized(this@PrivateApkCandidate) {
            current()
            if (finished || offset < 0 || length < 0 || offset > bytes.size - length || count + length > release.sizeBytes) changed()
            target.write(bytes, offset, length); count += length
        }
        override fun close() = synchronized(this@PrivateApkCandidate) {
            if (!finished) {
                try { if (!closed.get()) target.fd.sync() } finally { finished = true; target.close() }
            }
        }
    }
    private fun current() { if (closed.get()) changed() }
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        // Retire and unlink immediately. Account/navigation cancellation must
        // not wait for a platform inspector, disk hash or fd.sync under the lock.
        file.delete()
        writer?.takeIf { !it.finished }?.let { unfinished ->
            CoroutineScope(Dispatchers.IO).launch { runCatching { unfinished.close() }; file.delete() }
        }
    }
    override fun toString() = "PrivateApkCandidate"
    private fun changed(): Nothing = throw RemoteRequestException("update.state_changed")
    private fun integrity(): Nothing = throw RemoteRequestException("update.integrity_mismatch")
    private fun unavailable(): Nothing = throw RemoteRequestException("update.storage_unavailable")
}
