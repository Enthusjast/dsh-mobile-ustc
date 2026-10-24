package cn.edu.ustc.dsh.network

import cn.edu.ustc.dsh.protocol.RELAY_FRAME_BYTES
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class RelayFrameCodecTest {
    @Test fun advertisedLimitsAreRejectedBeforeReadingOrAllocatingPayload() {
        for (header in listOf(
            byteArrayOf(0x81.toByte(), 127, 0, 0, 0, 1, 0, 0, 0, 0),
            byteArrayOf(0x81.toByte(), 127, 0x7f, 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte(), 0xff.toByte()),
            byteArrayOf(0x89.toByte(), 126, 0, 126),
        )) {
            val input = object : ByteArrayInputStream(header) { override fun read(bytes: ByteArray, offset: Int, length: Int): Int = throw AssertionError("Oversized payload must not be read") }
            assertEquals("protocol.frame_too_large", assertThrows(RelayException::class.java) { RelayFrameCodec(input, ByteArrayOutputStream()).read(RELAY_FRAME_BYTES) }.code)
        }
    }

    @Test fun malformedMaskFlagsOpcodesLengthsCloseFramesAndTruncationAreRejected() {
        val bad = listOf(
            byteArrayOf(0x81.toByte(), 0x80.toByte()), byteArrayOf(0xc1.toByte(), 0), byteArrayOf(0x82.toByte(), 0),
            byteArrayOf(0x09, 0), byteArrayOf(0x81.toByte(), 126, 0, 1, 1),
            byteArrayOf(0x88.toByte(), 1, 0), byteArrayOf(0x88.toByte(), 2, 3, 0xee.toByte()),
            byteArrayOf(0x88.toByte(), 4, 3, 0xe8.toByte(), 0xc0.toByte(), 0x80.toByte()), byteArrayOf(0x81.toByte(), 5, 1),
        )
        bad.forEach { bytes -> assertThrows(RelayException::class.java) { RelayFrameCodec(ByteArrayInputStream(bytes), ByteArrayOutputStream()).read(RELAY_FRAME_BYTES) } }
        assertThrows(RelayException::class.java) { RelayFrameCodec(ByteArrayInputStream(byteArrayOf(0x80.toByte(), 2, 1, 2)), ByteArrayOutputStream()).read(1) }
    }

    @Test fun clientFramesAreMaskedAndPreserveScalarBytesAtEveryLengthBoundary() {
        for (size in listOf(0, 1, 125, 126, 65_535, 65_536)) {
            val bytes = ByteArray(size) { (it % 251).toByte() }
            val output = ByteArrayOutputStream()
            RelayFrameCodec(ByteArrayInputStream(byteArrayOf()), output).write(1, bytes)
            val wire = ByteArrayInputStream(output.toByteArray())
            assertEquals(0x81, wire.read())
            val tag = wire.read(); assertTrue(tag and 128 != 0)
            var length = (tag and 127).toLong()
            if (length == 126L) length = (wire.read() * 256 + wire.read()).toLong()
            else if (length == 127L) { length = 0; repeat(8) { length = (length shl 8) or wire.read().toLong() } }
            assertEquals(size.toLong(), length)
            val mask = ByteArray(4); assertEquals(4, wire.read(mask))
            val actual = ByteArray(size) { (wire.read() xor mask[it % 4].toInt()).toByte() }
            assertArrayEquals(bytes, actual); assertEquals(-1, wire.read())
        }
    }

    @Test fun arbitraryTruncatedHeadersStayWithinTheAdvertisedAllocationBudget() {
        val random = java.util.Random(90731)
        repeat(4096) {
            val header = ByteArray(random.nextInt(32)).also(random::nextBytes)
            val remaining = random.nextInt(RELAY_FRAME_BYTES + 1)
            try {
                val frame = RelayFrameCodec(ByteArrayInputStream(header), ByteArrayOutputStream()).read(remaining)
                assertTrue(frame.bytes.size <= RELAY_FRAME_BYTES)
                if (frame.opcode < 8) assertTrue(frame.bytes.size <= remaining)
            } catch (_: RelayException) { /* The only permitted rejection type; no native size/allocation exceptions. */ }
        }
    }
}
