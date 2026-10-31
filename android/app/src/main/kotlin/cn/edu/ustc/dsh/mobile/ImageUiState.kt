package cn.edu.ustc.dsh.mobile

import android.graphics.Bitmap

enum class DocumentPickPurpose { FILE, IMAGE, CAMERA }
data class ImagePreviewState(val bitmap: Bitmap, val name: String, val historical: Boolean)
data class SessionImageState(val preparing: Boolean = false, val preview: ImagePreviewState? = null, val previewRequested: Boolean = false,
    val previewLoading: Boolean = false, val error: String? = null)
