package cn.edu.ustc.dsh.mobile

import android.content.Intent
import android.content.pm.PackageManager
import android.os.Process
import androidx.core.content.FileProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_BYTES
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.nio.file.Files
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CameraCaptureStoreTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val directory = File(context.cacheDir, "session-camera")
    private val tracked = ArrayList<File>()

    @After fun removeOwnedFixtures() {
        // Remove links/directories themselves only; test fixtures never use recursive deletion.
        for (file in tracked.asReversed()) Files.deleteIfExists(file.toPath())
        // A count/size-limited first pass can intentionally leave bounded known-name residue.
        repeat(3) { try { CameraCaptureStore(context).cleanup() } catch (_: IOException) {} }
    }

    @Test fun oneTimeDestinationHasExactTokenPrivateProviderAndNoNewPermissions() {
        val store = CameraCaptureStore(context)
        val capture = store.create("owner-resource-revision-token")
        val uri = capture.uri
        assertEquals("owner-resource-revision-token", capture.token)
        assertEquals("content", uri.scheme)
        assertEquals(context.packageName + ".camera", uri.authority)
        assertEquals(directory.canonicalFile, capture.file.parentFile!!.canonicalFile)
        assertTrue(capture.current())
        context.contentResolver.openOutputStream(uri, "w")!!.use { it.write(byteArrayOf(1, 2, 3)) }
        assertArrayEquals(byteArrayOf(1, 2, 3), capture.file.readBytes())
        val provider = context.packageManager.resolveContentProvider(uri.authority!!, 0)!!
        assertFalse(provider.exported)
        assertTrue(provider.grantUriPermissions)
        val permissions = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_PERMISSIONS).requestedPermissions.orEmpty()
        assertFalse(permissions.contains("android.permission.CAMERA"))
        assertFalse(permissions.contains("android.permission.WRITE_EXTERNAL_STORAGE"))
        assertFalse(permissions.contains("android.permission.READ_EXTERNAL_STORAGE"))
        capture.close()
        capture.close()
        assertFalse(capture.current())
        assertFalse(capture.file.exists())
        assertThrows(java.io.FileNotFoundException::class.java) { context.contentResolver.openInputStream(uri) }
        store.create("next-token").use { assertNotEquals(uri, it.uri) }
        store.cleanup()
    }

    @Test fun closingRevokesExplicitCameraGrantAndNewCaptureInvalidatesOldDestination() {
        val store = CameraCaptureStore(context)
        val first = store.create("first")
        val testPackage = instrumentation.context.packageName
        val testUid = context.packageManager.getApplicationInfo(testPackage, 0).uid
        val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
        context.grantUriPermission(testPackage, first.uri, flags)
        assertEquals(PackageManager.PERMISSION_GRANTED, context.checkUriPermission(first.uri, -1, testUid, flags))
        val next = store.create("second")
        assertFalse(first.current())
        assertFalse(first.file.exists())
        if (testUid != Process.myUid()) {
            assertEquals(PackageManager.PERMISSION_DENIED, context.checkUriPermission(first.uri, -1, testUid, flags))
        }
        assertTrue(next.current())
        store.cleanup()
        assertFalse(next.current())
        assertFalse(next.file.exists())
    }

    @Test fun resultAboveSixteenMiBIsRevokedAndDeletedBeforeItCanBeCurrent() {
        val store = CameraCaptureStore(context)
        val capture = store.create("oversized")
        RandomAccessFile(capture.file, "rw").use { it.setLength(MAX_IMAGE_BYTES.toLong() + 1) }
        assertFalse(capture.current())
        assertFalse(capture.file.exists())
        store.create("maximum").use {
            RandomAccessFile(it.file, "rw").use { output -> output.setLength(MAX_IMAGE_BYTES.toLong()) }
            assertTrue(it.current())
        }
    }

    @Test fun captureExpiresAfterOneHundredEightySecondsEvenIfCameraTouchesTheFile() {
        val store = CameraCaptureStore(context)
        val capture = store.create("expired")
        // Move only this instance's monotonic origin: no wall-clock mutation or three-minute sleep.
        CameraCapture::class.java.getDeclaredField("createdAt").apply { isAccessible = true }
            .setLong(capture, android.os.SystemClock.elapsedRealtime() - 180_001L)
        assertTrue(capture.file.setLastModified(System.currentTimeMillis()))
        assertFalse(capture.current())
        assertFalse(capture.file.exists())
        assertFalse(capture.current())
    }

    @Test fun constructionAndCreateRemoveBothFreshAndExpiredKnownCrashResidue() {
        val store = CameraCaptureStore(context)
        val old = residue().apply { writeText("old camera bytes"); assertTrue(setLastModified(System.currentTimeMillis() - 181_000)) }
        val fresh = residue().apply { writeText("fresh interrupted camera bytes") }
        CameraCaptureStore(context)
        assertFalse(old.exists())
        assertFalse(fresh.exists())
        val between = residue().apply { writeText("interrupted after startup") }
        store.create("after-residue").use {
            assertFalse(between.exists())
            assertTrue(it.current())
        }
    }

    @Test fun cleanupIsCountAndSizeBoundedAndRefusesCreationUntilClear() {
        val store = CameraCaptureStore(context)
        val entries = (0..32).map { residue().apply { createNewFile() } }
        assertThrows(IOException::class.java) { store.create("count-limit") }
        assertTrue(entries.any { it.exists() })
        store.cleanup()
        assertTrue(entries.none { it.exists() })
        val huge = residue()
        RandomAccessFile(huge, "rw").use { it.setLength(MAX_IMAGE_BYTES.toLong() * 2 + 1) }
        assertThrows(IOException::class.java) { store.create("size-limit") }
        assertFalse(huge.exists())
        store.create("cleared").use { assertTrue(it.current()) }
    }

    @Test fun cleanupNeverRecursesOrFollowsSymlinksAndUnknownNamesBlockNewCapture() {
        val store = CameraCaptureStore(context)
        val unknown = File(directory, "unrecognized-private-file").also { tracked.add(it); it.writeText("preserve") }
        assertThrows(IOException::class.java) { store.create("unknown") }
        assertEquals("preserve", unknown.readText())
        Files.delete(unknown.toPath())
        val nested = residue().also { assertTrue(it.mkdir()) }
        val child = File(nested, "child").also { tracked.add(it); it.writeText("do not recurse") }
        assertThrows(IOException::class.java) { store.cleanup() }
        assertEquals("do not recurse", child.readText())
        Files.delete(child.toPath()); Files.delete(nested.toPath())
        val outside = File(context.cacheDir, "camera-outside-${UUID.randomUUID()}").also { tracked.add(it); it.writeText("outside") }
        val link = residue()
        Files.createSymbolicLink(link.toPath(), outside.toPath())
        assertThrows(IOException::class.java) { store.create("symlink") }
        assertEquals("outside", outside.readText())
        Files.delete(link.toPath())
        store.cleanup()
    }

    @Test fun providerCannotPublishAnyOtherCachePathAndSymlinkDirectoryIsRejected() {
        val store = CameraCaptureStore(context)
        val outside = File(context.cacheDir, "camera-unpublished-${UUID.randomUUID()}").also { tracked.add(it); it.writeText("private") }
        assertThrows(IllegalArgumentException::class.java) {
            FileProvider.getUriForFile(context, context.packageName + ".camera", outside)
        }
        store.cleanup()
        Files.delete(directory.toPath())
        val otherDirectory = File(context.cacheDir, "camera-other-${UUID.randomUUID()}").also { tracked.add(it); assertTrue(it.mkdir()) }
        try {
            Files.createSymbolicLink(directory.toPath(), otherDirectory.toPath())
            assertThrows(IOException::class.java) { CameraCaptureStore(context) }
        } finally {
            Files.deleteIfExists(directory.toPath())
        }
        assertTrue(otherDirectory.isDirectory)
    }

    private fun residue(): File = File(directory, "capture-${UUID.randomUUID()}.jpg").also { tracked.add(it) }
}
