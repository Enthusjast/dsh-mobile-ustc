package cn.edu.ustc.dsh.command

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test

class ImageIntentTest {
    private val request = "11111111-1111-4111-8111-111111111111"
    private val runtime = "22222222-2222-4222-8222-222222222222"
    private val session = "33333333-3333-4333-8333-333333333333"
    private val file = "44444444-4444-4444-8444-444444444444"
    private val other = "55555555-5555-4555-8555-555555555555"
    private val manifest = FileManifest("photo.png", 123, "a".repeat(64))
    private val image = ImageUploadMetadata("image/png", 640, 480)
    private fun message(images: List<String> = listOf(file), files: List<String> = emptyList()) =
        CommandIntent.message(request, runtime, session, "queue", "看图", files, images)

    @Test fun imageAdmissionIsExplicitAndChangesTheOriginalCommandDigest() {
        val visual = message()
        val generic = message(images = emptyList(), files = listOf(file))
        assertNotEquals(generic.digest, visual.digest)
        assertEquals(listOf(file), visual.fileIds()); assertEquals(listOf(file), visual.imageFileIds())
        assertEquals(listOf(file), generic.fileIds()); assertTrue(generic.imageFileIds().isEmpty())
        assertEquals("image", (visual.payload.array("content").last() as JsonObject).string("type"))
        assertEquals("file", (generic.payload.array("content").last() as JsonObject).string("type"))
        val restored = CommandIntent.stored(visual.storageBytes())
        assertEquals(visual.digest, restored.digest); assertEquals(visual.requestId, restored.requestId)
        assertEquals(visual.imageFileIds(), restored.imageFileIds())
        assertArrayEquals(visual.storageBytes(), restored.storageBytes())
        val mixed = message(files = listOf(other))
        assertEquals(listOf(other, file), mixed.fileIds()); assertEquals(listOf(file), mixed.imageFileIds())
        val only = CommandIntent.message(request, runtime, session, "steer", "", imageFileIds = listOf(file))
        assertEquals("", only.text()); assertEquals(1, only.payload.array("content").size)
    }

    @Test fun duplicateIdsAreRejectedWithinAndAcrossAttachmentTypes() {
        assertThrows(ProtocolException::class.java) { message(images = listOf(file, file)) }
        assertThrows(ProtocolException::class.java) { message(images = emptyList(), files = listOf(file, file)) }
        assertThrows(ProtocolException::class.java) { message(files = listOf(file)) }
        val root = message().frame()
        val imagePart = jsonObject("type" to "image".json(), "file_id" to file.json())
        for (bad in listOf(imagePart.with("url" to "https://example.invalid/photo.png".json()),
            imagePart.with("media_type" to "image/png".json()), imagePart.with("sha256" to manifest.sha256.json()),
            imagePart.with("path" to "/private/photo.png".json()), imagePart.with("type" to "Image".json()),
            jsonObject("type" to "image".json(), "url" to "https://example.invalid/photo.png".json()))) {
            assertThrows(ProtocolException::class.java) {
                CommandIntent.parse(root.with("payload" to jsonObject("mode" to "queue".json(), "content" to JsonArray(listOf(bad)))))
            }
        }
    }

    @Test fun genericLocalV1RemainsByteStableAndNeverInfersImagePurposeFromFilename() {
        val upload = FileUploadIntent(request, runtime, session, null, manifest)
        val expected = jsonObject("v" to 1L.json(), "request_id" to request.json(), "runtime_id" to runtime.json(),
            "session_id" to session.json(), "workspace_id" to JsonNull, "manifest" to manifest.json())
        assertArrayEquals(JsonDocument.of(expected).canonicalBytes(), upload.bytes())
        assertEquals(JsonDocument.of(expected).sha256(), upload.digest)
        val restored = FileUploadIntent.parse(upload.bytes())
        assertNull(restored.image); assertArrayEquals(upload.bytes(), restored.bytes())
        assertEquals(upload.digest, restored.digest)
        assertThrows(ProtocolException::class.java) { FileUploadIntent.parse(JsonDocument.of(expected.with("image" to image.json())).canonicalBytes()) }
    }

    @Test fun localV2BindsImagePurposeDimensionsAndDigestThroughResumeEvidence() {
        val upload = FileUploadIntent(request, runtime, session, other, manifest, image)
        val root = JsonDocument.parse(upload.bytes()).root
        assertEquals(2L, root.integer("v", 2, 2)); assertTrue(image.same(ImageUploadMetadata.parse(root.obj("image"))))
        val restored = FileUploadIntent.parse(upload.bytes())
        assertNotNull(restored.image); assertTrue(image.same(restored.image!!))
        assertArrayEquals(upload.bytes(), restored.bytes()); assertEquals(upload.digest, restored.digest)
        assertNotEquals(FileUploadIntent(request, runtime, session, other, manifest).digest, upload.digest)
        assertNotEquals(FileUploadIntent(request, runtime, session, other, manifest, ImageUploadMetadata("image/png", 641, 480)).digest, upload.digest)
        assertNotEquals(FileUploadIntent(request, runtime, session, other, FileManifest(manifest.name, manifest.sizeBytes, "b".repeat(64)), image).digest, upload.digest)
        val registered = StoredFileUpload(restored, file, request, 1000, 2000)
        assertEquals(file, registered.fileId); assertEquals(request, registered.messageId)
        assertEquals(upload.digest, registered.intent.digest); assertTrue(image.same(registered.intent.image!!))
        val original = message()
        val attempted = CommandEvolution.begin(CommandEvolution.created(original, 1000), 1001)
        val resumed = CommandEvolution.rearmUnboundFiles(attempted, 2000)
        assertNull(resumed.remote); assertFalse(resumed.everHostSaved); assertFalse(resumed.everAgentQueued)
        assertEquals(original.requestId, resumed.intent.requestId); assertEquals(original.digest, resumed.intent.digest)
        assertEquals(listOf(file), resumed.intent.imageFileIds())
        assertEquals(2L, CommandEvolution.begin(resumed, 2001).attempts)
    }

    @Test fun localUploadVersionsAndImageMetadataRemainStrict() {
        val root = JsonDocument.parse(FileUploadIntent(request, runtime, session, null, manifest, image).bytes()).root
        for (bad in listOf(root.with("v" to 0L.json()), root.with("v" to 3L.json()),
            JsonObject(root.fields.filterKeys { it != "image" }), root.with("image" to JsonNull),
            root.with("image" to image.json().with("purpose" to "image".json())),
            root.with("manifest" to manifest.json().with("sha256" to "broken".json())),
            root.with("source_uri" to "content://private/photo".json()), root.with("url" to "https://example.invalid".json()))) {
            assertThrows(ProtocolException::class.java) { FileUploadIntent.parse(JsonDocument.of(bad).canonicalBytes()) }
        }
        assertThrows(ProtocolException::class.java) { FileUploadIntent(request, runtime, session, null, FileManifest("empty.png", 0, manifest.sha256), image) }
        assertThrows(ProtocolException::class.java) { FileUploadIntent(request, runtime, session, null, FileManifest("large.png", MAX_IMAGE_BYTES + 1L, manifest.sha256), image) }
    }
}
