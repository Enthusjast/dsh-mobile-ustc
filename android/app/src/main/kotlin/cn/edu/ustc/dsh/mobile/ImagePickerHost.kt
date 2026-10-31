package cn.edu.ustc.dsh.mobile

import android.app.Activity
import android.content.ClipData
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.MediaStore
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContract
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_BYTES

/** System camera only; the controller owns the one-time output URI and its cleanup. */
internal class ImageCaptureContract : ActivityResultContract<Uri, Boolean>() {
    override fun createIntent(context: Context, input: Uri): Intent = Intent(MediaStore.ACTION_IMAGE_CAPTURE).apply {
        putExtra(MediaStore.EXTRA_OUTPUT, input)
        putExtra(MediaStore.EXTRA_SIZE_LIMIT, MAX_IMAGE_BYTES.toLong())
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
        clipData = ClipData.newRawUri("camera-output", input)
    }

    override fun parseResult(resultCode: Int, intent: Intent?): Boolean = resultCode == Activity.RESULT_OK
}

/**
 * Keep this composable mounted even when launch is null. A physical platform request
 * owns its original opaque token until its callback; a newer request cannot replace it.
 * Only the token/purpose bookkeeping survives Activity recreation, never a URI or grant.
 */
@Composable
fun MediaPickerEffect(launch: DocumentPickLaunch?, onPicked: (String, Uri?) -> Unit) {
    var physicalToken by rememberSaveable { mutableStateOf<String?>(null) }
    var physicalPurpose by rememberSaveable { mutableStateOf<String?>(null) }
    var completedToken by rememberSaveable { mutableStateOf<String?>(null) }
    val currentLaunch by rememberUpdatedState(launch)
    val currentResult by rememberUpdatedState(onPicked)

    fun finish(purpose: DocumentPickPurpose, uri: Uri?, cameraSuccess: Boolean = false) {
        val token = physicalToken ?: return
        if (physicalPurpose != purpose.name) return
        val pending = currentLaunch
        val matches = pending != null && pending.id == token && pending.purpose == purpose
        val result = if (!matches) null else if (purpose == DocumentPickPurpose.CAMERA) {
            if (cameraSuccess) pending?.output else null
        } else uri
        physicalToken = null
        physicalPurpose = null
        completedToken = token
        currentResult(token, result)
    }

    val document = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) {
        finish(DocumentPickPurpose.FILE, it)
    }
    val gallery = rememberLauncherForActivityResult(ActivityResultContracts.PickVisualMedia()) {
        finish(DocumentPickPurpose.IMAGE, it)
    }
    val camera = rememberLauncherForActivityResult(ImageCaptureContract()) {
        finish(DocumentPickPurpose.CAMERA, null, cameraSuccess = it)
    }

    LaunchedEffect(launch?.id, launch?.purpose) {
        val pending = launch ?: return@LaunchedEffect
        if (completedToken == pending.id) return@LaunchedEffect
        if (physicalToken != null) {
            if (physicalToken != pending.id || physicalPurpose != pending.purpose.name) {
                // Fail only the new request. Never hand it the older request's result.
                completedToken = pending.id
                currentResult(pending.id, null)
            }
            return@LaunchedEffect
        }
        if (pending.purpose == DocumentPickPurpose.CAMERA && pending.output == null) {
            completedToken = pending.id
            currentResult(pending.id, null)
            return@LaunchedEffect
        }
        // Mark the original request before launch: synchronous registry callbacks are legal.
        physicalToken = pending.id
        physicalPurpose = pending.purpose.name
        try {
            when (pending.purpose) {
                DocumentPickPurpose.FILE -> document.launch(arrayOf("*/*"))
                DocumentPickPurpose.IMAGE -> gallery.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageOnly))
                DocumentPickPurpose.CAMERA -> camera.launch(requireNotNull(pending.output))
            }
        } catch (_: ActivityNotFoundException) {
            finish(pending.purpose, null)
        } catch (_: SecurityException) {
            finish(pending.purpose, null)
        }
    }
}
