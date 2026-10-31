package cn.edu.ustc.dsh.mobile

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.SystemClock
import androidx.core.content.FileProvider
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_BYTES
import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.BasicFileAttributes
import java.util.UUID
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit

/** One foreground camera destination. Construct and call on the caller's I/O dispatcher. */
class CameraCaptureStore(context: Context) {
    private val context = context.applicationContext
    private val directory = File(this.context.cacheDir, "session-camera").toPath()
    private var capture: CameraCapture? = null

    init { cleanup() }

    fun create(token: String): CameraCapture = synchronized(CameraCapture.lock) {
        require(token.isNotEmpty()) { "camera.invalid_token" }
        cleanup()
        val file = directory.resolve("capture-${UUID.randomUUID()}.jpg").toFile()
        Files.createFile(file.toPath())
        try {
            val uri = FileProvider.getUriForFile(context, context.packageName + ".camera", file)
            CameraCapture(context, token, uri, file).also { capture = it }
        } catch (error: Throwable) {
            try { Files.deleteIfExists(file.toPath()) } catch (cleanup: Throwable) { error.addSuppressed(cleanup) }
            throw error
        }
    }

    /** Also clears one-time grants left by a crashed process; never traverses arbitrary paths. */
    fun cleanup(): Unit = synchronized(CameraCapture.lock) {
        capture?.close()
        capture = null
        ensureDirectory()
        var count = 0
        var bytes = 0L
        Files.newDirectoryStream(directory).use { entries ->
            for (path in entries) {
                if (++count > MAX_RESIDUE_COUNT) throw IOException("camera.cleanup_count_limit")
                if (!CAPTURE_NAME.matches(path.fileName.toString())) throw IOException("camera.unexpected_cache_entry")
                val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                if (!attributes.isRegularFile || attributes.isSymbolicLink) throw IOException("camera.unsafe_cache_entry")
                bytes += attributes.size()
                // All unowned files are crash residue, including files younger than the 180s TTL.
                // No file contents are read, even for oversized or old camera results.
                val uri = FileProvider.getUriForFile(context, context.packageName + ".camera", path.toFile())
                try {
                    context.revokeUriPermission(uri, CAMERA_GRANTS)
                } finally {
                    Files.delete(path)
                }
                if (bytes > MAX_RESIDUE_BYTES) throw IOException("camera.cleanup_size_limit")
            }
        }
    }

    private fun ensureDirectory() {
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory)
        val attributes = Files.readAttributes(directory, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        if (!attributes.isDirectory || attributes.isSymbolicLink) throw IOException("camera.unsafe_cache_directory")
    }

    private companion object {
        const val MAX_RESIDUE_COUNT = 32
        const val MAX_RESIDUE_BYTES = 2L * MAX_IMAGE_BYTES
        val CAPTURE_NAME = Regex("capture-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.jpg")
    }
}

private const val CAMERA_GRANTS = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION

class CameraCapture internal constructor(
    private val context: Context,
    val token: String,
    val uri: Uri,
    val file: File,
) : AutoCloseable {
    private val createdAt = SystemClock.elapsedRealtime()
    private var closed = false
    private val expiry: ScheduledFuture<*> = timer.schedule({ close() }, LIFETIME_MILLIS, TimeUnit.MILLISECONDS)

    fun current(): Boolean = synchronized(lock) {
        if (closed) return false
        val age = SystemClock.elapsedRealtime() - createdAt
        val attributes = try {
            Files.readAttributes(file.toPath(), BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        } catch (_: IOException) {
            close()
            return false
        }
        if (age !in 0 until LIFETIME_MILLIS || !attributes.isRegularFile || attributes.isSymbolicLink ||
            attributes.size() !in 0..MAX_IMAGE_BYTES.toLong()) {
            close()
            return false
        }
        true
    }

    override fun close(): Unit = synchronized(lock) {
        closed = true
        expiry.cancel(false)
        try {
            context.revokeUriPermission(uri, CAMERA_GRANTS)
        } finally {
            // Delete the destination itself, never follow any replacement symbolic link.
            Files.deleteIfExists(file.toPath())
        }
    }

    internal companion object {
        val lock = Any()
        private const val LIFETIME_MILLIS = 180_000L
        private val timer = ScheduledThreadPoolExecutor(1) { runnable ->
            Thread(runnable, "camera-capture-expiry").apply { isDaemon = true }
        }.apply { removeOnCancelPolicy = true }
    }
}
