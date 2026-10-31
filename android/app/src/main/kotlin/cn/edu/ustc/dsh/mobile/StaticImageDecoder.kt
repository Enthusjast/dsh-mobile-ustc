package cn.edu.ustc.dsh.mobile

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.graphics.ColorSpace
import android.graphics.Matrix
import cn.edu.ustc.dsh.protocol.ImageUploadMetadata
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_BYTES
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_DIMENSION
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_PIXELS
import cn.edu.ustc.dsh.protocol.MAX_PREVIEW_BITMAP_BYTES
import cn.edu.ustc.dsh.protocol.MAX_PREVIEW_EDGE
import cn.edu.ustc.dsh.protocol.MAX_PREVIEW_PIXELS

class DecodedStaticImage(val bitmap: Bitmap, val metadata: ImageUploadMetadata) : AutoCloseable {
    override fun close() { bitmap.recycle() }
}

/** No streams, retained input, disk cache, animation playback, or image re-encoding. */
object StaticImageDecoder {
    fun decode(bytes: ByteArray, expected: ImageUploadMetadata? = null): DecodedStaticImage {
        require(bytes.size in 10..MAX_IMAGE_BYTES) { "image.invalid" }
        val mime = magic(bytes)
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
        require(bounds.outMimeType == mime) { "image.invalid" }
        val width = bounds.outWidth
        val height = bounds.outHeight
        require(width in 1..MAX_IMAGE_DIMENSION && height in 1..MAX_IMAGE_DIMENSION &&
            width.toLong() * height <= MAX_IMAGE_PIXELS) { "image.too_large" }
        // These are encoded raster dimensions, not the sampled/oriented preview dimensions.
        val metadata = ImageUploadMetadata(mime, width, height)
        require(expected == null || metadata.same(expected)) { "image.metadata_mismatch" }
        val orientation = ExifOrientation.read(bytes, mime)
        var sample = 1
        while ((width + sample - 1) / sample > MAX_PREVIEW_EDGE ||
            (height + sample - 1) / sample > MAX_PREVIEW_EDGE ||
            ((width + sample - 1) / sample).toLong() * ((height + sample - 1) / sample) > MAX_PREVIEW_PIXELS) {
            sample *= 2
        }
        val options = BitmapFactory.Options().apply {
            inSampleSize = sample
            inPreferredConfig = Bitmap.Config.ARGB_8888
            inPreferredColorSpace = ColorSpace.get(ColorSpace.Named.SRGB)
            inScaled = false
            inDensity = 0
            inTargetDensity = 0
        }
        var bitmap = requireNotNull(BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)) { "image.invalid" }
        try {
            require(options.outMimeType == mime && bounded(bitmap)) { "image.too_large" }
            if (orientation != 1) {
                val matrix = Matrix().apply {
                    when (orientation) {
                        2 -> setScale(-1f, 1f)
                        3 -> setRotate(180f)
                        4 -> setScale(1f, -1f)
                        5 -> setValues(floatArrayOf(0f, 1f, 0f, 1f, 0f, 0f, 0f, 0f, 1f))
                        6 -> setRotate(90f)
                        7 -> setValues(floatArrayOf(0f, -1f, 0f, -1f, 0f, 0f, 0f, 0f, 1f))
                        8 -> setRotate(270f)
                    }
                }
                // Two bounded ARGB_8888 bitmaps coexist only here: at most 32 MiB.
                val oriented = Bitmap.createBitmap(bitmap, 0, 0, bitmap.width, bitmap.height, matrix, false)
                if (oriented !== bitmap) {
                    bitmap.recycle()
                    bitmap = oriented
                }
                require(bounded(bitmap)) { "image.too_large" }
            }
            return DecodedStaticImage(bitmap, metadata)
        } catch (error: Throwable) {
            bitmap.recycle()
            throw error
        }
    }

    private fun bounded(bitmap: Bitmap) = bitmap.config == Bitmap.Config.ARGB_8888 &&
        bitmap.width in 1..MAX_PREVIEW_EDGE && bitmap.height in 1..MAX_PREVIEW_EDGE &&
        bitmap.width.toLong() * bitmap.height <= MAX_PREVIEW_PIXELS &&
        bitmap.allocationByteCount <= MAX_PREVIEW_BITMAP_BYTES

    private fun magic(bytes: ByteArray): String = when {
        bytes.size >= 8 && bytes[0] == 0x89.toByte() && ascii(bytes, 1, "PNG\r\n\u001a\n") -> "image/png"
        bytes[0] == 0xff.toByte() && bytes[1] == 0xd8.toByte() && bytes[2] == 0xff.toByte() -> "image/jpeg"
        ascii(bytes, 0, "GIF87a") || ascii(bytes, 0, "GIF89a") -> "image/gif"
        bytes.size >= 12 && ascii(bytes, 0, "RIFF") && ascii(bytes, 8, "WEBP") -> "image/webp"
        else -> throw IllegalArgumentException("image.invalid")
    }

    private fun ascii(bytes: ByteArray, offset: Int, text: String): Boolean {
        if (offset < 0 || offset > bytes.size - text.length) return false
        for (index in text.indices) if ((bytes[offset + index].toInt() and 255) != text[index].code) return false
        return true
    }

    /** Only bounded container/IFD metadata is parsed here; BitmapFactory is always the raster decoder. */
    private object ExifOrientation {
        private const val MAX_EXIF_BYTES = 256 * 1024
        private const val MAX_IFD_ENTRIES = 256

        fun read(bytes: ByteArray, mime: String): Int {
            var result = 1
            var seen = false
            fun exif(start: Int, length: Int) {
                require(!seen && length in 8..MAX_EXIF_BYTES) { "image.invalid_exif" }
                seen = true
                var offset = start
                var size = length
                if (ascii(bytes, offset, "Exif\u0000\u0000")) { offset += 6; size -= 6 }
                result = tiff(bytes, offset, size)
            }
            when (mime) {
                "image/jpeg" -> {
                    var at = 2
                    while (at < bytes.size) {
                        require(u8(bytes, at++) == 255) { "image.invalid" }
                        while (at < bytes.size && u8(bytes, at) == 255) at++
                        require(at < bytes.size) { "image.invalid" }
                        val marker = u8(bytes, at++)
                        if (marker == 0xda || marker == 0xd9) break
                        if (marker == 1 || marker in 0xd0..0xd7) continue
                        require(at <= bytes.size - 2) { "image.invalid" }
                        val length = u8(bytes, at) * 256 + u8(bytes, at + 1)
                        require(length >= 2 && length <= bytes.size - at) { "image.invalid" }
                        if (marker == 0xe1 && length >= 8 && ascii(bytes, at + 2, "Exif\u0000\u0000")) exif(at + 2, length - 2)
                        at += length
                    }
                }
                "image/png" -> {
                    var at = 8
                    while (at <= bytes.size - 12) {
                        val length = uint(bytes, at, false)
                        require(length <= bytes.size - at - 12L) { "image.invalid" }
                        if (ascii(bytes, at + 4, "eXIf")) exif(at + 8, length.toInt())
                        val end = ascii(bytes, at + 4, "IEND")
                        at += length.toInt() + 12
                        if (end) break
                    }
                }
                "image/webp" -> {
                    require(uint(bytes, 4, true) + 8 == bytes.size.toLong()) { "image.invalid" }
                    var at = 12
                    while (at <= bytes.size - 8) {
                        val length = uint(bytes, at + 4, true)
                        val padded = length + (length and 1)
                        require(padded <= bytes.size - at - 8L) { "image.invalid" }
                        if (ascii(bytes, at, "EXIF")) exif(at + 8, length.toInt())
                        at += padded.toInt() + 8
                    }
                    require(at == bytes.size) { "image.invalid" }
                }
            }
            return result
        }

        private fun tiff(bytes: ByteArray, base: Int, length: Int): Int {
            require(length >= 8) { "image.invalid_exif" }
            val little = ascii(bytes, base, "II")
            require(little || ascii(bytes, base, "MM")) { "image.invalid_exif" }
            fun short(offset: Int): Int {
                require(offset >= 0 && offset <= length - 2) { "image.invalid_exif" }
                val first = u8(bytes, base + offset)
                val second = u8(bytes, base + offset + 1)
                return if (little) first + second * 256 else first * 256 + second
            }
            fun word(offset: Int): Long {
                require(offset >= 0 && offset <= length - 4) { "image.invalid_exif" }
                return uint(bytes, base + offset, little)
            }
            require(short(2) == 42) { "image.invalid_exif" }
            val ifd = word(4)
            if (ifd == 0L) return 1
            require(ifd >= 8 && ifd <= length - 2L) { "image.invalid_exif" }
            val start = ifd.toInt()
            val count = short(start)
            require(count <= MAX_IFD_ENTRIES && count * 12L + 6 <= length - start) { "image.invalid_exif" }
            var orientation = 1
            var seen = false
            for (entry in 0 until count) {
                val at = start + 2 + entry * 12
                if (short(at) == 0x112) {
                    require(!seen && short(at + 2) == 3 && word(at + 4) == 1L) { "image.invalid_exif" }
                    orientation = short(at + 8)
                    require(orientation in 1..8) { "image.invalid_exif" }
                    seen = true
                }
            }
            return orientation
        }

        private fun u8(bytes: ByteArray, offset: Int) = bytes[offset].toInt() and 255
        private fun uint(bytes: ByteArray, offset: Int, little: Boolean): Long {
            var value = 0L
            for (index in 0..3) {
                val at = if (little) offset + 3 - index else offset + index
                value = (value shl 8) or u8(bytes, at).toLong()
            }
            return value
        }
    }
}
