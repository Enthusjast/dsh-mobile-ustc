package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.*
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class SessionMediaMemoryTest {
    private fun reference() = VisibleMediaReference.parse(jsonObject("v" to 1L.json(), "origin" to "session_attachment".json(), "native_seq" to 0L.json(),
        "part_index" to 0L.json(), "event_version_sha256" to "a".repeat(64).json(),
        "manifest" to ExportManifest("image.png", 4, "b".repeat(64)).json(), "media_type" to "image/png".json(), "width" to 1L.json(), "height" to 1L.json()))

    @Test fun previewCloseZerosTheOwnedBytesAndCannotBeReadAgain() {
        val bytes = byteArrayOf(1, 2, 3, 4)
        val memory = VerifiedMediaBytes(reference(), bytes)
        assertEquals(4, memory.read { it.size })
        assertEquals("VerifiedMediaBytes", memory.toString())
        memory.close(); memory.close()
        assertArrayEquals(ByteArray(4), bytes)
        assertThrows(RemoteRequestException::class.java) { memory.read { it.copyOf() } }
    }

    @Test fun revocationCannotMutateARealDecoderReadHalfwayThroughItsInput() {
        val bytes = byteArrayOf(1, 2, 3, 4)
        val memory = VerifiedMediaBytes(reference(), bytes)
        val entered = CountDownLatch(1); val release = CountDownLatch(1); val closed = CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val decoder = Thread {
            try { memory.read { input -> entered.countDown(); check(release.await(5, TimeUnit.SECONDS)); assertArrayEquals(byteArrayOf(1, 2, 3, 4), input) } }
            catch (error: Throwable) { failure.set(error) }
        }
        decoder.start(); assertTrue(entered.await(5, TimeUnit.SECONDS))
        val revoke = Thread { memory.close(); closed.countDown() }
        revoke.start()
        try {
            assertFalse(closed.await(20, TimeUnit.MILLISECONDS))
        } finally { release.countDown(); decoder.join(5000); revoke.join(5000) }
        failure.get()?.let { throw AssertionError(it) }
        assertEquals(0L, closed.count); assertArrayEquals(ByteArray(4), bytes)
        assertThrows(RemoteRequestException::class.java) { memory.read { it.size } }
    }
}
