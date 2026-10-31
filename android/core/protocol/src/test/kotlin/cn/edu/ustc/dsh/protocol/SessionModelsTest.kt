package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class SessionModelsTest {
    private fun fixture(name: String) = JsonDocument.parse(File(System.getProperty("contracts.root"), "ws/v1/golden/$name.json").readBytes()).root
    private fun result() = fixture("session-models.result")
    private fun payload(root: JsonObject, vararg fields: Pair<String, JsonValue>) = root.with("payload" to root.obj("payload").with(*fields))
    private fun item(id: String = "m", label: String = "model", efforts: List<JsonValue> = emptyList()) = jsonObject(
        "provider" to jsonObject("id" to "p".json(), "label" to "provider".json()),
        "model" to jsonObject("id" to id.json(), "label" to label.json()), "reasoning_efforts" to JsonArray(efforts))
    private fun label(id: String, text: String = id) = jsonObject("id" to id.json(), "label" to text.json())

    @Test fun sharedFixturesRoundTripWithoutRenamingNativeIdsOrInventingCurrentSelection() {
        val get = SessionModelsGet.parse(fixture("session-models.get"))
        assertEquals(25, get.limit); assertNull(get.cursor)
        assertEquals(JsonDocument.of(fixture("session-models.get")).canonicalText(), JsonDocument.of(get.frame()).canonicalText())
        val page = SessionModelsResult.parse(result())
        assertEquals(get.binding, page.binding); assertEquals(get.requestId, page.requestId)
        assertEquals("fixture", page.items.single().provider.id)
        assertEquals("offline", page.items.single().model.id)
        assertEquals("high", page.items.single().reasoningEfforts.single().id)
        assertEquals(1, page.unavailableProviderCount); assertNull(page.nextCursor)
        val opaque = "  原样/模型<&🙂  "
        val parsed = SessionModelsResult.parse(payload(result(), "items" to JsonArray(listOf(item(opaque)))))
        assertEquals(opaque, parsed.items.single().model.id)
    }
    @Test fun queryLimitsCursorAndSelectorsAreStrict() {
        val root = fixture("session-models.get")
        for (limit in listOf(1, 50)) assertEquals(limit, SessionModelsGet.parse(payload(root, "limit" to limit.toLong().json())).limit)
        for (limit in listOf(0, 51)) assertThrows(ProtocolException::class.java) { SessionModelsGet.parse(payload(root, "limit" to limit.toLong().json())) }
        for (cursor in listOf(JsonNull, "".json(), "x".repeat(1025).json(), 1L.json()))
            assertThrows(ProtocolException::class.java) { SessionModelsGet.parse(payload(root, "cursor" to cursor)) }
        assertEquals("x".repeat(1024), SessionModelsGet.parse(payload(root, "cursor" to "x".repeat(1024).json())).cursor)
        assertThrows(ProtocolException::class.java) { SessionModelsGet.parse(payload(root, "provider" to "p".json())) }
        assertThrows(ProtocolException::class.java) { SessionModelsGet.parse(root.with("sync_id" to getSync(root).json())) }
    }
    private fun getSync(root: JsonObject) = root.obj("payload").string("sync_id")
    @Test fun itemFieldsIdsLabelsEffortsAndProviderFailureCountFailClosed() {
        val base = result()
        fun reject(value: JsonObject) = assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(payload(base, "items" to JsonArray(listOf(value)))) }
        reject(item().with("description" to "private".json()))
        reject(item("")); reject(item("x".repeat(129))); reject(item(label = "x".repeat(257)))
        for (bad in listOf("", "bad\u0000", "bad\n", "bad\u007f", "\ud800")) reject(item(label = bad))
        reject(item(efforts = List(33) { label("e$it") }))
        reject(item(efforts = listOf(label("same"), label("same"))))
        reject(item(efforts = listOf(label("x".repeat(65)))))
        assertEquals(32, SessionModelsResult.parse(payload(base, "items" to JsonArray(listOf(item(efforts = List(32) { label("e$it") }))))).items.single().reasoningEfforts.size)
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(payload(base, "items" to JsonArray(List(51) { item("m$it") }))) }
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(payload(base, "items" to JsonArray(listOf(item(), item())))) }
        for (count in listOf(-1, 129)) assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(payload(base, "unavailable_provider_count" to count.toLong().json())) }
        assertEquals(128, SessionModelsResult.parse(payload(base, "unavailable_provider_count" to 128L.json())).unavailableProviderCount)
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(payload(base, "next_cursor" to "".json())) }
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(payload(base, "items" to JsonArray(emptyList()), "next_cursor" to "more".json())) }
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(base.with("configuration" to jsonObject())) }
    }
    private fun byteBudgetFrame(target: Int): JsonObject {
        val labels = IntArray(150) { 1 }
        fun build() = payload(result(), "items" to JsonArray(List(50) { i -> item("m$i", "x".repeat(labels[i * 3 + 1]),
            listOf(label("e", "x".repeat(labels[i * 3 + 2])))).with("provider" to label("p", "x".repeat(labels[i * 3]))) }),
            "unavailable_provider_count" to 0L.json())
        var remaining = target - JsonDocument.of(build()).canonicalBytes().size
        for (i in labels.indices) {
            val add = minOf(remaining, 255); labels[i] += add; remaining -= add
        }
        check(remaining == 0)
        return build()
    }
    @Test fun pageBudgetIncludesExactBoundaryAndRelayEscapingCost() {
        val exact = byteBudgetFrame(SESSION_MODELS_PAGE_BYTES)
        assertEquals(SESSION_MODELS_PAGE_BYTES, SessionModelsResult.parse(exact).encodedBytes)
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(byteBudgetFrame(SESSION_MODELS_PAGE_BYTES + 1)) }
        val item = exact.obj("payload").array("items").first() as JsonObject
        val changed = item.with("provider" to item.obj("provider").with("label" to ("<" + item.obj("provider").string("label").drop(1)).json()))
        val escaped = payload(exact, "items" to JsonArray(listOf(changed) + exact.obj("payload").array("items").drop(1)))
        assertEquals(SESSION_MODELS_PAGE_BYTES, JsonDocument.of(escaped).canonicalBytes().size)
        assertThrows(ProtocolException::class.java) { SessionModelsResult.parse(escaped) }
    }
    @Test fun fixedErrorsRetainFullBindingAndForbidPrivateErrorBodies() {
        val base = result()
        for (code in SessionModelsError.codes) {
            val frame = base.with("type" to "session.models.error".json(), "payload" to jsonObject("code" to code.json()))
            val error = SessionModelsError.parse(frame)
            assertEquals(SessionModelsResult.parse(base).binding, error.binding); assertEquals(code, error.code)
            assertThrows(ProtocolException::class.java) { SessionModelsError.parse(payload(frame, "message" to "provider secret".json())) }
        }
        assertThrows(ProtocolException::class.java) { SessionModelsError.parse(base.with("type" to "session.models.error".json(), "payload" to jsonObject("code" to "provider.failed".json()))) }
    }
}
