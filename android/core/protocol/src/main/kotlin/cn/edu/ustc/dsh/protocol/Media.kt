package cn.edu.ustc.dsh.protocol

import org.erdtman.jcs.JsonCanonicalizer

const val IMAGE_MESSAGE_CAPABILITY = "message.images.v1"
const val SESSION_MEDIA_CAPABILITY = "session.media.v1"
const val MAX_IMAGE_BYTES = 16 * 1024 * 1024
const val MAX_IMAGE_PIXELS = 32_000_000L
const val MAX_IMAGE_DIMENSION = 16_384
const val MAX_PREVIEW_EDGE = 2048
const val MAX_PREVIEW_PIXELS = 4_194_304L
const val MAX_PREVIEW_BITMAP_BYTES = 16 * 1024 * 1024
const val LEGACY_IMAGE_NOTICE = "[图片：需支持图片预览的客户端与独立下载授权]"
val STATIC_IMAGE_MEDIA_TYPES: Set<String> = setOf("image/png", "image/jpeg", "image/webp", "image/gif")

/** Validated local image purpose, not authorization and never inferred from a filename. */
class ImageUploadMetadata(val mediaType: String, val width: Int, val height: Int) {
    init {
        if (mediaType !in STATIC_IMAGE_MEDIA_TYPES || width !in 1..MAX_IMAGE_DIMENSION || height !in 1..MAX_IMAGE_DIMENSION ||
            width.toLong() * height > MAX_IMAGE_PIXELS) throw ProtocolException()
    }
    fun json() = jsonObject("media_type" to mediaType.json(), "width" to width.toLong().json(), "height" to height.toLong().json())
    fun same(other: ImageUploadMetadata) = mediaType == other.mediaType && width == other.width && height == other.height
    override fun toString() = "ImageUploadMetadata"
    companion object {
        fun parse(root: JsonObject): ImageUploadMetadata {
            root.exactKeys("media_type", "width", "height")
            return ImageUploadMetadata(root.string("media_type"), root.integer("width", 1, MAX_IMAGE_DIMENSION.toLong()).toInt(), root.integer("height", 1, MAX_IMAGE_DIMENSION.toLong()).toInt())
        }
    }
}

/** Stable visible-event provenance. A reference is never file.download authority. */
class VisibleMediaReference private constructor(val nativeSeq: Long, val partIndex: Int, val eventVersionSha256: String,
    val manifest: ExportManifest, val image: ImageUploadMetadata) {
    fun json() = jsonObject("v" to 1L.json(), "origin" to "session_attachment".json(), "native_seq" to nativeSeq.json(),
        "part_index" to partIndex.toLong().json(), "event_version_sha256" to eventVersionSha256.json(), "manifest" to manifest.json(),
        "media_type" to image.mediaType.json(), "width" to image.width.toLong().json(), "height" to image.height.toLong().json())
    fun same(other: VisibleMediaReference) = nativeSeq == other.nativeSeq && partIndex == other.partIndex && eventVersionSha256 == other.eventVersionSha256 && manifest.same(other.manifest) && image.same(other.image)
    override fun toString() = "VisibleMediaReference"
    companion object {
        fun parse(root: JsonObject): VisibleMediaReference {
            root.exactKeys("v", "origin", "native_seq", "part_index", "event_version_sha256", "manifest", "media_type", "width", "height")
            root.integer("v", 1, 1)
            if (root.string("origin") != "session_attachment") throw ProtocolException()
            val manifest = ExportManifest.parse(root.obj("manifest"))
            if (manifest.sizeBytes !in 1..MAX_IMAGE_BYTES.toLong()) throw ProtocolException()
            val image = ImageUploadMetadata(root.string("media_type"), root.integer("width", 1, MAX_IMAGE_DIMENSION.toLong()).toInt(), root.integer("height", 1, MAX_IMAGE_DIMENSION.toLong()).toInt())
            return VisibleMediaReference(root.integer("native_seq", 0), root.integer("part_index", 0, 4095).toInt(), Contract.digest(root.string("event_version_sha256")), manifest, image)
        }
    }
}

/** Input has already passed the bounded SessionJson grammar; this does not widen signing JSON limits. */
fun mediaEventSha256(encodedSessionEvent: ByteArray): String {
    if (encodedSessionEvent.size > 2 * 1024 * 1024) throw ProtocolException()
    return try { sha256(JsonCanonicalizer(encodedSessionEvent.toString(Charsets.UTF_8)).encodedString.toByteArray(Charsets.UTF_8)) }
    catch (_: Exception) { throw ProtocolException() }
}
