package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test

class MediaTest {
    private val digest = "a".repeat(64)
    private fun reference() = jsonObject("v" to 1L.json(), "origin" to "session_attachment".json(),
        "native_seq" to 7L.json(), "part_index" to 2L.json(), "event_version_sha256" to digest.json(),
        "manifest" to ExportManifest("图片.png", 123, digest).json(),
        "media_type" to "image/png".json(), "width" to 640L.json(), "height" to 480L.json())

    @Test fun typedReferenceRoundTripsWithoutIntroducingDownloadAuthority() {
        val root = reference()
        val parsed = VisibleMediaReference.parse(root)
        assertEquals(7L, parsed.nativeSeq); assertEquals(2, parsed.partIndex)
        assertEquals(digest, parsed.eventVersionSha256)
        assertEquals("图片.png", parsed.manifest.name)
        assertEquals(123L, parsed.manifest.sizeBytes)
        assertEquals("image/png", parsed.image.mediaType)
        assertEquals(640, parsed.image.width); assertEquals(480, parsed.image.height)
        assertTrue(parsed.same(VisibleMediaReference.parse(JsonDocument.parse(JsonDocument.of(parsed.json()).canonicalBytes()).root)))
        assertArrayEquals(JsonDocument.of(root).canonicalBytes(), JsonDocument.of(parsed.json()).canonicalBytes())
        assertFalse(parsed.toString().contains("图片"))
        for (mime in STATIC_IMAGE_MEDIA_TYPES) {
            assertEquals(mime, VisibleMediaReference.parse(root.with("media_type" to mime.json())).image.mediaType)
        }
        assertEquals(0L, VisibleMediaReference.parse(root.with("native_seq" to 0L.json(), "part_index" to 0L.json())).nativeSeq)
        assertEquals(4095, VisibleMediaReference.parse(root.with("part_index" to 4095L.json())).partIndex)
        assertEquals(MAX_IMAGE_BYTES.toLong(), VisibleMediaReference.parse(root.with("manifest" to root.obj("manifest").with("size_bytes" to MAX_IMAGE_BYTES.toLong().json()))).manifest.sizeBytes)
    }

    @Test fun referencesRejectUnknownVersionsOriginsDigestsAndNonIntegerProvenance() {
        val root = reference()
        val invalid = listOf(root.with("v" to 0L.json()), root.with("v" to 2L.json()),
            root.with("origin" to "workspace_artifact".json()), root.with("origin" to "https://example.invalid/image".json()),
            root.with("native_seq" to (-1L).json()), root.with("part_index" to (-1L).json()), root.with("part_index" to 4096L.json()),
            root.with("native_seq" to "7".json()), root.with("part_index" to JsonDocument.parse("{\"n\":1.5}").root["n"]),
            root.with("event_version_sha256" to "A".repeat(64).json()), root.with("event_version_sha256" to "a".repeat(63).json()),
            root.with("event_version_sha256" to "g".repeat(64).json()), root.with("event_version_sha256" to JsonNull))
        for (bad in invalid) assertThrows(ProtocolException::class.java) { VisibleMediaReference.parse(bad) }
        for (key in root.fields.keys) {
            assertThrows(ProtocolException::class.java) { VisibleMediaReference.parse(JsonObject(root.fields.filterKeys { it != key })) }
        }
    }

    @Test fun manifestsCannotSmugglePathsUrlsAuthorityOrOversizedImages() {
        val root = reference()
        val manifest = root.obj("manifest")
        for (bad in listOf(manifest.with("name" to "../secret.png".json()), manifest.with("name" to "a\\b.png".json()),
            manifest.with("size_bytes" to 0L.json()), manifest.with("size_bytes" to (MAX_IMAGE_BYTES.toLong() + 1).json()),
            manifest.with("sha256" to "broken".json()), manifest.with("sha256" to "A".repeat(64).json()),
            manifest.with("url" to "https://example.invalid/image".json()), manifest.with("unknown" to JsonNull))) {
            assertThrows(ProtocolException::class.java) { VisibleMediaReference.parse(root.with("manifest" to bad)) }
        }
        for (key in listOf("url", "download_url", "signed_url", "path", "file_id", "source_id", "unknown")) {
            assertThrows(ProtocolException::class.java) { VisibleMediaReference.parse(root.with(key to "https://example.invalid/image".json())) }
        }
    }

    @Test fun metadataAllowsOnlyBoundedStaticImageTypesAndExactKeys() {
        val root = reference()
        for (mime in listOf("image/svg+xml", "text/html", "image/PNG", "image/png; charset=utf-8", "https://example.invalid/a.png")) {
            assertThrows(ProtocolException::class.java) { VisibleMediaReference.parse(root.with("media_type" to mime.json())) }
        }
        for (bad in listOf(root.with("width" to 0L.json()), root.with("height" to (-1L).json()),
            root.with("width" to (MAX_IMAGE_DIMENSION + 1L).json()), root.with("height" to (MAX_IMAGE_DIMENSION + 1L).json()),
            root.with("width" to 8000L.json(), "height" to 4001L.json()), root.with("width" to "640".json()))) {
            assertThrows(ProtocolException::class.java) { VisibleMediaReference.parse(bad) }
        }
        val limit = ImageUploadMetadata("image/png", 8000, 4000)
        assertTrue(limit.same(ImageUploadMetadata.parse(limit.json())))
        assertEquals(MAX_IMAGE_DIMENSION, ImageUploadMetadata("image/gif", MAX_IMAGE_DIMENSION, 1).width)
        assertThrows(ProtocolException::class.java) { ImageUploadMetadata.parse(limit.json().with("url" to "https://example.invalid".json())) }
    }
}
