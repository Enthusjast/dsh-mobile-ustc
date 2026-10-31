package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.time.Instant
import java.util.Base64
import java.util.UUID

class SessionChangesTest {
    private fun id() = UUID.randomUUID().toString()
    private val binding = SessionActionBinding(id(), id(), id(), id(), id())
    private val snapshot = id()
    private val file = id()
    private val version = "a".repeat(64)
    private val capabilities = setOf("session.read.v1", SESSION_CHANGES_CAPABILITY)
    private fun manifest(query: JsonObject, expires: Long, expectedBytes: Int, complete: Boolean = true, kind: String = "text"): JsonObject {
        val path = jsonObject("bytes_base64" to "YQ==".json(), "display" to "a".json())
        val row = jsonObject("file_id" to file.json(), "status" to "modified".json(), "old_path" to path, "new_path" to path,
            "old_mode" to "100644".json(), "new_mode" to "100644".json(), "kind" to kind.json(), "patch_bytes" to expectedBytes.toLong().json(),
            "complete" to JsonBoolean(complete), "copyable" to JsonBoolean(false))
        return query.with("type" to "session.changes.result".json(), "sync_id" to binding.syncId.json(), "payload" to jsonObject(
            "v" to 1L.json(), "sync_id" to binding.syncId.json(), "snapshot_id" to snapshot.json(), "source" to "configured_workspace_git".json(),
            "base" to jsonObject("kind" to "git_head".json(), "oid" to "b".repeat(40).json()), "version" to version.json(), "manifest_sha256" to "c".repeat(64).json(),
            "expires_at" to Instant.ofEpochMilli(expires).toString().json(), "scope" to "tracked_head_to_index_worktree".json(),
            "excluded" to JsonArray(listOf("untracked".json(), "ignored".json(), "submodule_contents".json())), "complete" to JsonBoolean(true), "truncated" to JsonBoolean(false),
            "files" to JsonArray(listOf(row)), "next_cursor" to JsonNull))
    }
    private fun patch(query: JsonObject, text: String, next: String? = null, kind: String = "text") = query.with("type" to "session.changes.patch.result".json(),
        "sync_id" to binding.syncId.json(), "payload" to jsonObject("v" to 1L.json(), "sync_id" to binding.syncId.json(), "snapshot_id" to snapshot.json(), "file_id" to file.json(),
            "version" to version.json(), "kind" to kind.json(), "complete" to JsonBoolean(false), "copyable" to JsonBoolean(false), "partial" to JsonBoolean(true),
            "patch_base64" to Base64.getEncoder().encodeToString(text.toByteArray()).json(), "patch_utf8" to text.json(), "hunks" to JsonArray(emptyList()), "next_cursor" to (next?.json() ?: JsonNull)))
    private fun ready(book: SessionChanges, sends: MutableList<JsonObject>, alive: () -> Boolean = { true }) {
        book.connected(capabilities, true); book.ready(binding, alive) { sends += it }
    }
    @Test fun exactFullPatchIsAvailableOnlyAfterAllPagesAndExpiresWithoutReplay(): Unit = runBlocking {
        var wall = 1_700_000_000_000L; var nano = 1L
        val sends = arrayListOf<JsonObject>()
        val first = "diff --git a/a b/a\n"; val second = "--- a/a\n+++ b/a\n"; val third = "@@ -1 +1 @@\n-old\n+新\n"
        SessionChanges({ nano }, { wall }).use { book ->
            ready(book, sends); assertTrue(sends.isEmpty()); assertTrue(book.loadInitial()); assertFalse(book.reload())
            assertTrue(book.accept(manifest(sends.last(), wall + 30_000, (first + second + third).toByteArray().size)))
            assertTrue(book.loadPatch(file)); assertTrue(book.accept(patch(sends.last(), first, id())))
            assertTrue(book.state.value.patch!!.partial); assertNull(book.completePatch()); assertFalse(book.state.value.canCopyComplete)
            assertTrue(book.loadNextPatch()); assertTrue(book.accept(patch(sends.last(), second, id())))
            assertEquals(second, book.state.value.patch!!.patchUtf8)
            assertEquals(Base64.getEncoder().encodeToString(second.toByteArray()), book.state.value.patch!!.patchBase64)
            assertTrue(book.state.value.patch!!.partial); assertNull(book.completePatch()); assertFalse(book.state.value.canCopyComplete)
            assertTrue(book.loadNextPatch()); assertTrue(book.accept(patch(sends.last(), third)))
            assertEquals(first + second + third, book.completePatch()); assertTrue(book.state.value.canCopyComplete); assertFalse(book.state.value.patch!!.partial)
            assertEquals(Base64.getEncoder().encodeToString((first + second + third).toByteArray()), book.state.value.patch!!.patchBase64)
            val count = sends.size
            wall += 30_000; nano += 30_000_000_000; book.tick()
            assertEquals(SessionChangesPhase.STALE, book.state.value.phase); assertNull(book.completePatch()); assertNull(book.state.value.patch)
            assertTrue(book.state.value.files.isEmpty()); assertEquals(count, sends.size); assertFalse(book.loadNextPatch())
        }
    }
    @Test fun fullyAccumulatedInvalidUtf8NeverAuthorizesCopy(): Unit = runBlocking {
        val wall = 1_700_000_000_000L; val sends = arrayListOf<JsonObject>()
        SessionChanges(wallClock = { wall }).use { book ->
            ready(book, sends); book.loadInitial(); book.accept(manifest(sends.last(), wall + 30_000, 3))
            book.loadPatch(file); book.accept(patch(sends.last(), "a\n", id())); book.loadNextPatch()
            val fragment = patch(sends.last(), "")
            val invalid = fragment.with("payload" to fragment.obj("payload").with("patch_base64" to "/w==".json(), "patch_utf8" to JsonNull))
            assertTrue(book.accept(invalid)); assertFalse(book.state.value.canCopyComplete); assertNull(book.completePatch())
            assertTrue(book.state.value.patch!!.partial); assertFalse(book.state.value.patchHasMore)
            book.disconnected(); assertNull(book.state.value.patch)
        }
    }
    @Test fun mismatchedBindingsAndVersionsNeverAccumulatePatchBytes(): Unit = runBlocking {
        val wall = 1_700_000_000_000L; val sends = arrayListOf<JsonObject>()
        SessionChanges(wallClock = { wall }).use { book ->
            ready(book, sends); book.loadInitial(); val page = manifest(sends.last(), wall + 30_000, 2)
            for (key in listOf("request_id", "runtime_id", "runtime_epoch", "session_id", "subscription_id", "sync_id")) assertFalse(book.accept(page.with(key to id().json())))
            book.accept(page); book.loadPatch(file)
            val wrong = patch(sends.last(), "a\n").let { it.with("payload" to it.obj("payload").with("version" to "d".repeat(64).json())) }
            book.accept(wrong); assertEquals(SessionChangesPhase.STALE, book.state.value.phase); assertNull(book.completePatch()); assertNull(book.state.value.patch)
        }
    }
    @Test fun binaryIncompleteWrongLengthAndRevokedPatchesNeverEnableCompleteCopy(): Unit = runBlocking {
        val wall = 1_700_000_000_000L
        for ((kind, complete, expectedBytes) in listOf(Triple("binary", false, 2), Triple("text", false, 2), Triple("text", true, 3))) {
            val sends = arrayListOf<JsonObject>()
            SessionChanges(wallClock = { wall }).use { book ->
                ready(book, sends); book.loadInitial(); book.accept(manifest(sends.last(), wall + 30_000, expectedBytes, complete, kind)); book.loadPatch(file)
                book.accept(patch(sends.last(), "a\n", kind = kind)); assertNull(book.completePatch()); assertFalse(book.state.value.canCopyComplete)
                book.disconnected("access.revoked"); assertEquals(SessionChangesPhase.DENIED, book.state.value.phase); assertNull(book.state.value.patch)
            }
        }
    }
    @Test fun unsupportedDeniedTimeoutAndExpiredReadersNeverIssueImplicitRequests(): Unit = runBlocking {
        var nano = 1L; var alive = true; val sends = arrayListOf<JsonObject>()
        SessionChanges(clock = { nano }, queryMillis = 1).use { book ->
            book.connected(capabilities, false); book.ready(binding, { alive }) { sends += it }; assertFalse(book.loadInitial())
            assertEquals(SessionChangesPhase.DENIED, book.state.value.phase)
            book.connected(emptySet(), true); assertEquals(SessionChangesPhase.UNAVAILABLE, book.state.value.phase)
            ready(book, sends) { alive }; book.loadInitial(); nano += 1_000_000; book.tick()
            assertEquals("network.changes_timeout", book.state.value.error); assertEquals(1, sends.size)
            alive = false; book.tick(); assertEquals(SessionChangesPhase.STALE, book.state.value.phase); assertFalse(book.reload())
            book.close(); assertEquals(SessionChangesPhase.CLOSED, book.state.value.phase)
        }
    }
    @Test fun reopeningAPatchAcceptsStableHostCursorsButCyclesWithinOneReadStayRejected(): Unit = runBlocking {
        val wall = 1_700_000_000_000L
        val sends = arrayListOf<JsonObject>()
        val first = "first\n"; val last = "last\n"; val next = id()
        SessionChanges(wallClock = { wall }).use { book ->
            ready(book, sends)
            assertTrue(book.loadInitial())
            assertTrue(book.accept(manifest(sends.last(), wall + 30_000, (first + last).toByteArray().size)))
            repeat(2) {
                assertTrue(book.loadPatch(file))
                assertTrue(book.accept(patch(sends.last(), first, next)))
                assertEquals(SessionChangesPhase.READY, book.state.value.phase)
                assertNull(book.completePatch())
                assertTrue(book.loadNextPatch())
                assertTrue(book.accept(patch(sends.last(), last)))
                assertEquals(first + last, book.completePatch())
                assertTrue(book.state.value.canCopyComplete)
            }
            assertTrue(book.loadPatch(file))
            assertTrue(book.accept(patch(sends.last(), first, next)))
            assertTrue(book.loadNextPatch())
            assertTrue(book.accept(patch(sends.last(), last, next)))
            assertEquals(SessionChangesPhase.STALE, book.state.value.phase)
            assertNull(book.completePatch())
            assertFalse(book.state.value.canCopyComplete)
        }
    }
}
