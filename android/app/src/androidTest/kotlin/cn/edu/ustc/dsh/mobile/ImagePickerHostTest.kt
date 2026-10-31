package cn.edu.ustc.dsh.mobile

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.provider.MediaStore
import androidx.activity.ComponentActivity
import androidx.activity.compose.LocalActivityResultRegistryOwner
import androidx.activity.result.ActivityResultRegistry
import androidx.activity.result.ActivityResultRegistryOwner
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.app.ActivityOptionsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_BYTES
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ImagePickerHostTest {
    @get:Rule val rule = createAndroidComposeRule<ComponentActivity>()
    private data class Invocation(val requestCode: Int, val contract: ActivityResultContract<*, *>, val intent: Intent)
    private inner class Registry : ActivityResultRegistry(), ActivityResultRegistryOwner {
        override val activityResultRegistry: ActivityResultRegistry get() = this
        val calls = mutableListOf<Invocation>()
        var synchronousCancel = false
        override fun <I, O> onLaunch(requestCode: Int, contract: ActivityResultContract<I, O>, input: I, options: ActivityOptionsCompat?) {
            calls += Invocation(requestCode, contract, contract.createIntent(rule.activity, input))
            if (synchronousCancel) dispatchResult(requestCode, Activity.RESULT_CANCELED, null)
        }
        fun respond(call: Invocation, result: Int = Activity.RESULT_OK, uri: Uri? = null) {
            dispatchResult(call.requestCode, result, uri?.let { Intent().setData(it) })
        }
    }

    @Test fun galleryUsesImagesOnlyAndReturnsTheOriginalToken() {
        val registry = Registry()
        val pending = mutableStateOf<DocumentPickLaunch?>(DocumentPickLaunch("gallery-original", DocumentPickPurpose.IMAGE))
        val results = mutableListOf<Pair<String, Uri?>>()
        rule.setContent { CompositionLocalProvider(LocalActivityResultRegistryOwner provides registry) {
            MediaPickerEffect(pending.value) { id, uri -> results += id to uri; pending.value = null }
        } }
        rule.runOnIdle {
            val call = registry.calls.single()
            assertTrue(call.contract is ActivityResultContracts.PickVisualMedia)
            assertEquals("image/*", call.intent.type)
            registry.respond(call, uri = Uri.parse("content://picker/selected"))
        }
        rule.runOnIdle { assertEquals(listOf("gallery-original" to Uri.parse("content://picker/selected")), results) }
    }

    @Test fun cameraUsesOnlyControllerOutputWithOneTimeReadWriteGrantsAndSizeLimit() {
        val registry = Registry()
        val output = Uri.parse("content://owned-camera/one-time.jpg")
        val results = mutableListOf<Pair<String, Uri?>>()
        rule.setContent { CompositionLocalProvider(LocalActivityResultRegistryOwner provides registry) {
            MediaPickerEffect(DocumentPickLaunch("camera-original", DocumentPickPurpose.CAMERA, output)) { id, uri -> results += id to uri }
        } }
        rule.runOnIdle {
            val call = registry.calls.single()
            assertEquals(MediaStore.ACTION_IMAGE_CAPTURE, call.intent.action)
            @Suppress("DEPRECATION")
            assertEquals(output, call.intent.getParcelableExtra<Uri>(MediaStore.EXTRA_OUTPUT))
            assertEquals(MAX_IMAGE_BYTES.toLong(), call.intent.getLongExtra(MediaStore.EXTRA_SIZE_LIMIT, -1))
            assertEquals(output, call.intent.clipData!!.getItemAt(0).uri)
            assertTrue(call.intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
            assertTrue(call.intent.flags and Intent.FLAG_GRANT_WRITE_URI_PERMISSION != 0)
            assertEquals(0, call.intent.flags and Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
            registry.respond(call, uri = Uri.parse("content://untrusted-camera/different"))
        }
        rule.runOnIdle { assertEquals(listOf("camera-original" to output), results) }
    }

    @Test fun savedTokenPreventsRotationRelaunchAndPreservesOriginalCallback() {
        val registry = Registry()
        val restore = StateRestorationTester(rule)
        val pending = mutableStateOf<DocumentPickLaunch?>(DocumentPickLaunch("before-rotation", DocumentPickPurpose.IMAGE))
        val results = mutableListOf<Pair<String, Uri?>>()
        restore.setContent { CompositionLocalProvider(LocalActivityResultRegistryOwner provides registry) {
            MediaPickerEffect(pending.value) { id, uri -> results += id to uri; pending.value = null }
        } }
        rule.runOnIdle { assertEquals(1, registry.calls.size) }
        restore.emulateSavedInstanceStateRestore()
        rule.runOnIdle {
            assertEquals("Recreation must not reopen the system picker", 1, registry.calls.size)
            registry.respond(registry.calls.single(), uri = Uri.parse("content://picker/rotated"))
        }
        rule.runOnIdle { assertEquals(listOf("before-rotation" to Uri.parse("content://picker/rotated")), results) }
    }

    @Test fun newerTokenFailsWithoutReplacingPendingPhysicalResultAcrossRotation() {
        val registry = Registry()
        val restore = StateRestorationTester(rule)
        val pending = mutableStateOf<DocumentPickLaunch?>(DocumentPickLaunch("old", DocumentPickPurpose.IMAGE))
        val results = mutableListOf<Pair<String, Uri?>>()
        restore.setContent { CompositionLocalProvider(LocalActivityResultRegistryOwner provides registry) {
            MediaPickerEffect(pending.value) { id, uri -> results += id to uri }
        } }
        rule.runOnIdle { pending.value = DocumentPickLaunch("new", DocumentPickPurpose.FILE) }
        rule.runOnIdle {
            assertEquals(listOf("new" to null), results)
            assertEquals(1, registry.calls.size)
        }
        restore.emulateSavedInstanceStateRestore()
        rule.runOnIdle {
            assertEquals(1, registry.calls.size)
            registry.respond(registry.calls.single(), uri = Uri.parse("content://picker/must-not-cross-context"))
        }
        rule.runOnIdle {
            assertEquals(listOf("new" to null, "old" to null), results)
            pending.value = DocumentPickLaunch("third", DocumentPickPurpose.FILE)
        }
        rule.runOnIdle {
            assertEquals(2, registry.calls.size)
            assertTrue(registry.calls.last().contract is ActivityResultContracts.OpenDocument)
            registry.respond(registry.calls.last(), Activity.RESULT_CANCELED)
        }
        rule.runOnIdle { assertEquals("third" to null, results.last()) }
    }

    @Test fun exitDiscardsLateUriAndSynchronousCancellationIsTokenBound() {
        val registry = Registry()
        val pending = mutableStateOf<DocumentPickLaunch?>(DocumentPickLaunch("exited", DocumentPickPurpose.IMAGE))
        val results = mutableListOf<Pair<String, Uri?>>()
        rule.setContent { CompositionLocalProvider(LocalActivityResultRegistryOwner provides registry) {
            MediaPickerEffect(pending.value) { id, uri -> results += id to uri }
        } }
        rule.runOnIdle { pending.value = null }
        rule.runOnIdle { registry.respond(registry.calls.single(), uri = Uri.parse("content://picker/late-private-uri")) }
        rule.runOnIdle {
            assertEquals(listOf("exited" to null), results)
            registry.synchronousCancel = true
            pending.value = DocumentPickLaunch("synchronous", DocumentPickPurpose.IMAGE)
        }
        rule.runOnIdle { assertEquals("synchronous" to null, results.last()) }
    }

    @Test fun missingCameraOutputNeverLaunchesAndCameraCancellationNeverReturnsBytes() {
        val registry = Registry()
        val pending = mutableStateOf<DocumentPickLaunch?>(DocumentPickLaunch("missing-output", DocumentPickPurpose.CAMERA))
        val results = mutableListOf<Pair<String, Uri?>>()
        rule.setContent { CompositionLocalProvider(LocalActivityResultRegistryOwner provides registry) {
            MediaPickerEffect(pending.value) { id, uri -> results += id to uri }
        } }
        rule.runOnIdle {
            assertEquals(listOf("missing-output" to null), results)
            assertTrue(registry.calls.isEmpty())
            pending.value = DocumentPickLaunch("camera-cancel", DocumentPickPurpose.CAMERA, Uri.parse("content://owned-camera/cancelled"))
        }
        rule.runOnIdle { registry.respond(registry.calls.single(), Activity.RESULT_CANCELED) }
        rule.runOnIdle { assertEquals("camera-cancel" to null, results.last()) }
    }
}
