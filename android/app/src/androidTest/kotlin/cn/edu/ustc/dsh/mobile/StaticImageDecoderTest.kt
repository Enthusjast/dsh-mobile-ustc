package cn.edu.ustc.dsh.mobile

import android.graphics.Bitmap
import android.graphics.Color
import androidx.test.ext.junit.runners.AndroidJUnit4
import cn.edu.ustc.dsh.protocol.ImageUploadMetadata
import cn.edu.ustc.dsh.protocol.MAX_IMAGE_BYTES
import cn.edu.ustc.dsh.protocol.MAX_PREVIEW_BITMAP_BYTES
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.util.zip.CRC32

@RunWith(AndroidJUnit4::class)
class StaticImageDecoderTest {
    @Test fun realPlatformDecodesAllFourFormatsAndCloseRecyclesWithoutChangingInput() {
        for ((format, mime) in formats) {
            val bytes = encoded(format)
            val original = bytes.copyOf()
            val image = StaticImageDecoder.decode(bytes, ImageUploadMetadata(mime, 6, 4))
            assertEquals(mime, image.metadata.mediaType)
            assertEquals(6, image.bitmap.width)
            assertEquals(4, image.bitmap.height)
            assertFalse(image.bitmap.isRecycled)
            image.close()
            image.close()
            assertTrue(image.bitmap.isRecycled)
            assertArrayEquals(original, bytes)
        }
        // A real two-frame GIF: the second (blue) frame must never replace frame zero (red).
        val gif = hex("47494638396102000100800000ff00000000ff" +
            "2c0000000002000100000202040a00" + "2c00000000020001000002024c0a00" + "3b")
        StaticImageDecoder.decode(gif, ImageUploadMetadata("image/gif", 2, 1)).use {
            assertEquals(Color.RED, it.bitmap.getPixel(0, 0))
            assertEquals(Color.RED, it.bitmap.getPixel(1, 0))
        }
    }

    @Test fun allEightOrientationsAreAppliedForJpegPngAndWebpIncludingBigEndianTiff() {
        for ((format, mime) in formats) {
            val bytes = encoded(format)
            StaticImageDecoder.decode(bytes).use { baseline ->
                for (orientation in 1..8) {
                    val withExif = orient(bytes, mime, tiff(orientation, little = mime != "image/png"))
                    StaticImageDecoder.decode(withExif, ImageUploadMetadata(mime, 6, 4)).use { decoded ->
                        // Admission metadata remains the original raster dimensions.
                        assertEquals(6, decoded.metadata.width)
                        assertEquals(4, decoded.metadata.height)
                        val swap = orientation >= 5
                        assertEquals(if (swap) 4 else 6, decoded.bitmap.width)
                        assertEquals(if (swap) 6 else 4, decoded.bitmap.height)
                        for (y in 0 until decoded.bitmap.height) for (x in 0 until decoded.bitmap.width) {
                            val source = when (orientation) {
                                2 -> (5 - x) to y
                                3 -> (5 - x) to (3 - y)
                                4 -> x to (3 - y)
                                5 -> y to x
                                6 -> y to (3 - x)
                                7 -> (5 - y) to (3 - x)
                                8 -> (5 - y) to x
                                else -> x to y
                            }
                            assertEquals("$mime orientation=$orientation x=$x y=$y",
                                baseline.bitmap.getPixel(source.first, source.second), decoded.bitmap.getPixel(x, y))
                        }
                    }
                }
            }
        }
    }

    @Test fun largeRealRasterIsSampledBeforeRotationAndWithinBitmapBudget() {
        val source = Bitmap.createBitmap(4096, 1024, Bitmap.Config.ARGB_8888)
        val bytes = try {
            source.eraseColor(Color.GREEN)
            ByteArrayOutputStream().use { output -> source.compress(Bitmap.CompressFormat.PNG, 100, output); output.toByteArray() }
        } finally { source.recycle() }
        StaticImageDecoder.decode(orient(bytes, "image/png", tiff(6))).use {
            assertEquals(4096, it.metadata.width)
            assertEquals(1024, it.metadata.height)
            assertEquals(512, it.bitmap.width)
            assertEquals(2048, it.bitmap.height)
            assertEquals(Bitmap.Config.ARGB_8888, it.bitmap.config)
            assertTrue(it.bitmap.allocationByteCount <= MAX_PREVIEW_BITMAP_BYTES)
        }
    }

    @Test fun forgedMimeBadRasterOversizedInputAndMetadataMismatchAreRejected() {
        val png = encoded(Bitmap.CompressFormat.PNG)
        val badInputs = listOf(
            "<svg xmlns=\"http://www.w3.org/2000/svg\"/>".toByteArray(),
            "<!doctype html><img src=https://example.invalid/image.png>".toByteArray(),
            "https://example.invalid/image.png".toByteArray(),
            hex("89504e470d0a1a0a0000000000000000"),
            hex("ffd8ffe000104a46494600000000000000000000"),
            ByteArray(MAX_IMAGE_BYTES + 1),
        )
        for (bytes in badInputs) assertThrows(IllegalArgumentException::class.java) { StaticImageDecoder.decode(bytes) }
        assertThrows(IllegalArgumentException::class.java) {
            StaticImageDecoder.decode(png, ImageUploadMetadata("image/jpeg", 6, 4))
        }
        assertThrows(IllegalArgumentException::class.java) {
            StaticImageDecoder.decode(png, ImageUploadMetadata("image/png", 4, 6))
        }
    }

    @Test fun predecodeBoundsRejectDimensionAndPixelBombs() {
        val png = encoded(Bitmap.CompressFormat.PNG)
        for ((width, height) in listOf(16385 to 1, 8000 to 4001, 0 to 4)) {
            val bomb = png.copyOf()
            put32(bomb, 16, width, false)
            put32(bomb, 20, height, false)
            put32(bomb, 29, CRC32().apply { update(bomb, 12, 17) }.value.toInt(), false)
            assertThrows(IllegalArgumentException::class.java) { StaticImageDecoder.decode(bomb) }
        }
    }

    @Test fun malformedOrAmbiguousExifNeverBecomesAnUnorientedSuccessfulPreview() {
        val png = encoded(Bitmap.CompressFormat.PNG)
        val badOffset = tiff(1).apply { put32(this, 4, Int.MAX_VALUE, true) }
        val badCount = tiff(1).apply { this[8] = 0xff.toByte(); this[9] = 0xff.toByte() }
        for (metadata in listOf(tiff(0), tiff(9), badOffset, badCount, ByteArray(256 * 1024 + 1))) {
            assertThrows(IllegalArgumentException::class.java) { StaticImageDecoder.decode(orient(png, "image/png", metadata)) }
        }
        val once = orient(png, "image/png", tiff(2))
        assertThrows(IllegalArgumentException::class.java) { StaticImageDecoder.decode(orient(once, "image/png", tiff(3))) }
        val webp = encoded(Bitmap.CompressFormat.WEBP).copyOf().apply { put32(this, 4, size + 100, true) }
        assertThrows(IllegalArgumentException::class.java) { StaticImageDecoder.decode(webp) }
    }

    private fun encoded(format: Bitmap.CompressFormat): ByteArray {
        val bitmap = Bitmap.createBitmap(6, 4, Bitmap.Config.ARGB_8888)
        try {
            bitmap.setHasAlpha(false)
            for (y in 0..3) for (x in 0..5) bitmap.setPixel(x, y, Color.rgb(20 + x * 35, 20 + y * 55, (x + y) * 20))
            return ByteArrayOutputStream().use { output ->
                assertTrue(bitmap.compress(format, 100, output))
                output.toByteArray()
            }
        } finally { bitmap.recycle() }
    }

    private fun tiff(orientation: Int, little: Boolean = true): ByteArray = ByteArray(26).apply {
        this[0] = (if (little) 'I' else 'M').code.toByte(); this[1] = this[0]
        fun short(at: Int, value: Int) {
            this[at] = (if (little) value else value shr 8).toByte()
            this[at + 1] = (if (little) value shr 8 else value).toByte()
        }
        short(2, 42); put32(this, 4, 8, little); short(8, 1)
        short(10, 0x112); short(12, 3); put32(this, 14, 1, little); short(18, orientation)
    }

    private fun orient(bytes: ByteArray, mime: String, tiff: ByteArray): ByteArray = when (mime) {
        "image/jpeg" -> {
            val payload = "Exif\u0000\u0000".toByteArray(Charsets.US_ASCII) + tiff
            val length = payload.size + 2
            bytes.copyOfRange(0, 2) + byteArrayOf(0xff.toByte(), 0xe1.toByte(), (length shr 8).toByte(), length.toByte()) +
                payload + bytes.copyOfRange(2, bytes.size)
        }
        "image/png" -> bytes.copyOfRange(0, 33) + pngChunk("eXIf", tiff) + bytes.copyOfRange(33, bytes.size)
        "image/webp" -> {
            val extended = ByteArray(10).apply { this[0] = 8; this[4] = 5; this[7] = 3 }
            val chunks = bytes.copyOfRange(12, bytes.size)
            val hasExtended = String(chunks, 0, 4, Charsets.US_ASCII) == "VP8X"
            val raster = if (hasExtended) chunks.apply { this[8] = (this[8].toInt() or 8).toByte() }
                else webpChunk("VP8X", extended) + chunks
            val body = "WEBP".toByteArray() + raster + webpChunk("EXIF", tiff)
            "RIFF".toByteArray() + ByteArray(4).apply { put32(this, 0, body.size, true) } + body
        }
        else -> error("Unsupported test format")
    }

    private fun pngChunk(kind: String, data: ByteArray): ByteArray {
        val body = kind.toByteArray(Charsets.US_ASCII) + data
        val crc = CRC32().apply { update(body) }.value.toInt()
        return ByteArray(4).apply { put32(this, 0, data.size, false) } + body + ByteArray(4).apply { put32(this, 0, crc, false) }
    }

    private fun webpChunk(kind: String, data: ByteArray): ByteArray = kind.toByteArray(Charsets.US_ASCII) +
        ByteArray(4).apply { put32(this, 0, data.size, true) } + data + ByteArray(data.size and 1)

    private fun put32(bytes: ByteArray, at: Int, value: Int, little: Boolean) {
        for (index in 0..3) bytes[at + index] = (value ushr (if (little) index * 8 else (3 - index) * 8)).toByte()
    }

    private fun hex(text: String) = ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    private val formats = listOf(Bitmap.CompressFormat.PNG to "image/png", Bitmap.CompressFormat.JPEG to "image/jpeg",
        Bitmap.CompressFormat.WEBP to "image/webp")
}
