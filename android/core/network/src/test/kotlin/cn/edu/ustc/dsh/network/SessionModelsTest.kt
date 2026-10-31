package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.command.CommandDataException
import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.util.UUID

class SessionModelsTest {
    private val fixture = JsonDocument.parse(File(System.getProperty("contracts.root"), "ws/v1/golden/session-models.result.json").readBytes()).root
    private val binding = SessionModelsResult.parse(fixture).binding
    private val capabilities = setOf("session.read.v1", SESSION_MODELS_CAPABILITY, "command.relay.v1", SESSION_MODEL_SELECT_CAPABILITY)
    private fun page(query: JsonObject, items: List<JsonValue> = fixture.obj("payload").array("items"), cursor: String? = null, unavailable: Int = 0): JsonObject =
        query.with("type" to "session.models.result".json(), "sync_id" to query.obj("payload").string("sync_id").json(),
            "payload" to jsonObject("items" to JsonArray(items), "next_cursor" to (cursor?.json() ?: JsonNull), "unavailable_provider_count" to unavailable.toLong().json()))
    private fun item(id: String, provider: String = "p", label: String = id) = jsonObject("provider" to jsonObject("id" to provider.json(), "label" to provider.json()),
        "model" to jsonObject("id" to id.json(), "label" to label.json()), "reasoning_efforts" to JsonArray(emptyList()))
    private fun ready(book: SessionModels, sends: MutableList<JsonObject>, accepted: SessionModelBinding = binding, alive: () -> Boolean = { true }) {
        book.connected(capabilities, true)
        book.ready(accepted, false, alive) { sends += it }
    }
    @Test fun explicitPagesAreBoundedSerializedAndNeverAutoFetchOrReload(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>()
        SessionModels(null).use { book ->
            ready(book, sends)
            assertEquals(SessionModelCatalogPhase.IDLE, book.state.value.phase); assertTrue(sends.isEmpty())
            assertTrue(book.loadInitial(1)); assertFalse(book.loadInitial()); assertFalse(book.loadNext()); assertFalse(book.reload())
            assertEquals(1, book.state.value.inFlight)
            book.accept(page(sends.single(), listOf(item("a")), "opaque /游标<&", 1))
            assertEquals(SessionModelCatalogPhase.PARTIAL, book.state.value.phase)
            assertTrue(book.state.value.hasMore); assertEquals(1, sends.size)
            assertTrue(book.loadNext(50)); assertEquals("opaque /游标<&", sends.last().obj("payload").string("cursor"))
            book.accept(page(sends.last(), listOf(item("b")), unavailable = 1))
            assertEquals(listOf("a", "b"), book.state.value.items.map { it.model.id })
            assertFalse(book.state.value.hasMore); assertFalse(book.loadNext())
            val context = book.state.value.contextId
            assertTrue(book.reload()); assertTrue(book.state.value.contextId > context)
            val error = page(sends.last()).with("type" to "session.models.error".json(), "payload" to jsonObject("code" to "protocol.resync_required".json()))
            book.accept(error)
            assertEquals(SessionModelCatalogPhase.CATALOG_CHANGED, book.state.value.phase)
            assertTrue(book.state.value.items.isEmpty()); assertEquals(3, sends.size)
            book.tick(); book.tick(); assertEquals(3, sends.size); assertFalse(book.loadInitial())
            assertTrue(book.reload()); assertEquals(4, sends.size)
        }
    }
    @Test fun responseMustMatchEveryRequestRuntimeEpochSessionSubscriptionAndSyncIdentity(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>()
        SessionModels(null).use { book ->
            ready(book, sends); book.loadInitial()
            val valid = page(sends.single())
            for (field in listOf("request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "sync_id")) {
                assertFalse(book.accept(valid.with(field to UUID.randomUUID().toString().json())))
                assertEquals(SessionModelCatalogPhase.LOADING, book.state.value.phase)
            }
            assertTrue(book.accept(valid)); assertEquals(SessionModelCatalogPhase.READY, book.state.value.phase)
            assertFalse(book.accept(valid))
            book.disconnected(); val retired = book.state.value.contextId
            assertTrue(book.state.value.items.isEmpty()); assertFalse(book.loadInitial())
            ready(book, sends, binding.copy(syncId = UUID.randomUUID().toString(), subscriptionId = UUID.randomUUID().toString(), epoch = UUID.randomUUID().toString()))
            assertTrue(book.state.value.contextId > retired); book.loadInitial()
            assertFalse(book.accept(valid)); assertEquals(1, book.state.value.inFlight)
            assertTrue(book.accept(page(sends.last())))
        }
    }
    @Test fun timeoutPermissionMissingCapabilityAndOfflineAreNotSuccessfulEmptyDirectories(): Unit = runBlocking {
        var now = 1L
        val sends = arrayListOf<JsonObject>()
        SessionModels(null, clock = { now }, queryMillis = 5).use { book ->
            book.connected(capabilities, false); assertEquals(SessionModelCatalogPhase.DENIED, book.state.value.phase)
            book.ready(binding, false, { true }) { sends += it }; assertFalse(book.loadInitial())
            book.connected(setOf("session.read.v1"), true); assertEquals(SessionModelCatalogPhase.UNAVAILABLE, book.state.value.phase)
            book.ready(binding, false, { true }) { sends += it }; assertFalse(book.loadInitial())
            book.connected(capabilities, true); assertEquals(SessionModelCatalogPhase.SNAPSHOT_REQUIRED, book.state.value.phase); assertFalse(book.loadInitial())
            book.ready(binding, false, { true }) { sends += it }; book.loadInitial()
            val old = page(sends.single())
            now += 5_000_000; book.tick()
            assertEquals("network.models_timeout", book.state.value.error); assertEquals(0, book.state.value.inFlight)
            assertFalse(book.accept(old)); assertEquals(1, sends.size)
            book.reload(); book.accept(page(sends.last(), emptyList(), unavailable = 1))
            assertEquals(SessionModelCatalogPhase.PARTIAL, book.state.value.phase)
            book.reload(); book.accept(page(sends.last(), emptyList()))
            assertEquals(SessionModelCatalogPhase.EMPTY, book.state.value.phase)
            book.disconnected(); assertEquals(SessionModelCatalogPhase.OFFLINE, book.state.value.phase)
            assertThrows(CommandDataException::class.java) { runBlocking { book.select("fixture", "offline") } }
            book.close(); assertEquals(SessionModelCatalogPhase.CLOSED, book.state.value.phase); assertFalse(book.loadInitial())
        }
    }
    @Test fun catalogChangesDuplicateIdsLoopingCursorsAndServerLimitViolationsRetireTheDirectory(): Unit = runBlocking {
        suspend fun badSecond(first: List<JsonValue>, second: List<JsonValue>, cursor: String? = null, unavailable: Int = 0, expected: String) {
            val sends = arrayListOf<JsonObject>()
            SessionModels(null).use { book ->
                ready(book, sends); book.loadInitial(); book.accept(page(sends.last(), first, "cursor")); book.loadNext()
                book.accept(page(sends.last(), second, cursor, unavailable))
                assertEquals(expected, book.state.value.error); assertTrue(book.state.value.items.isEmpty()); assertFalse(book.state.value.hasMore)
            }
        }
        badSecond(listOf(item("a")), listOf(item("a")), expected = "protocol.invalid")
        badSecond(listOf(item("b")), listOf(item("a")), expected = "protocol.invalid")
        badSecond(listOf(item("a")), listOf(item("b")), cursor = "cursor", expected = "protocol.resync_required")
        badSecond(listOf(item("a")), listOf(item("b")), unavailable = 1, expected = "protocol.resync_required")
        val sends = arrayListOf<JsonObject>()
        SessionModels(null).use { book ->
            ready(book, sends); book.loadInitial(1); book.accept(page(sends.last(), listOf(item("a"), item("b"))))
            assertEquals("protocol.snapshot_too_large", book.state.value.error)
        }
    }
    @Test fun accumulationBoundsModelsProvidersAndEncodedMemoryWithoutUnboundedCursorRetention(): Unit = runBlocking {
        suspend fun bounded(make: (Int) -> List<JsonValue>, count: Int, expected: String) {
            val sends = arrayListOf<JsonObject>()
            SessionModels(null).use { book ->
                ready(book, sends); book.loadInitial(50)
                for (index in 0 until count) {
                    book.accept(page(sends.last(), make(index), "page-$index"))
                    if (book.state.value.error != null) break
                    sends.clear(); book.loadNext(50)
                }
                assertEquals(expected, book.state.value.error); assertTrue(book.state.value.items.isEmpty())
            }
        }
        bounded({ page -> List(50) { item("m%05d".format(page * 50 + it)) } }, 165, "protocol.snapshot_too_large")
        bounded({ page -> listOf(item("m", provider = "p%03d".format(page))) }, 129, "protocol.snapshot_too_large")
        // Each page fits 32 KiB, but the accumulated encoded projection crosses 4 MiB first.
        bounded({ page -> List(50) { item("m%05d".format(page * 50 + it), label = "中".repeat(150)) } }, 165, "protocol.snapshot_too_large")
    }
    @Test fun errorsAndScopeRetirementCannotBeResurrectedByRepeatedTranscriptPublication(): Unit = runBlocking {
        val sends = arrayListOf<JsonObject>(); var active = true
        SessionModels(null).use { book ->
            ready(book, sends, alive = { active }); book.loadInitial()
            val query = sends.single()
            val error = query.with("type" to "error".json(), "payload" to jsonObject("code" to "runtime.offline".json()))
            assertFalse(book.error(error.with("request_id" to UUID.randomUUID().toString().json()), "runtime.offline"))
            assertTrue(book.error(error, "runtime.offline")); val generation = book.state.value.contextId
            book.ready(binding, false, { active }) { sends += it }
            assertEquals(SessionModelCatalogPhase.OFFLINE, book.state.value.phase); assertEquals(generation, book.state.value.contextId)
            ready(book, sends, alive = { active }); book.loadInitial(); active = false
            assertFalse(book.accept(page(sends.last()))); assertFalse(book.reload())
            book.disconnected("access.revoked"); assertEquals(SessionModelCatalogPhase.DENIED, book.state.value.phase)
            assertTrue(book.state.value.contextId > generation)
        }
    }
    @Test fun localContextIdentityCannotCollideWhenReaderOwnersAreRecreated() {
        SessionModels(null).use { first ->
            val original = first.state.value.contextId
            first.disconnected("access.revoked")
            val retired = first.state.value.contextId
            assertTrue(retired > original)
            SessionModels(null).use { second -> assertTrue(second.state.value.contextId > retired) }
        }
    }
}
