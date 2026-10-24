package cn.edu.ustc.dsh.protocol

import org.junit.Assert.*
import org.junit.Test
import java.io.File

class CanonicalJsonTest {
    @Test fun `all shared JCS vectors match Go and TypeScript`() {
        val vectors = JsonDocument.parse("{\"vectors\":" + File(System.getProperty("contracts.root"), "security/jcs-vectors.json").readText() + "}").root.array("vectors")
        for (item in vectors) {
            val vector = item as JsonObject
            val name = vector.string("name")
            val input = (vector.fields["input_base64"] as? JsonString)?.let { java.util.Base64.getDecoder().decode(it.value) }
                ?: vector.string("input").toByteArray(Charsets.UTF_8)
            if (vector.fields["invalid"] == JsonBoolean(true)) {
                assertThrows(name, ProtocolException::class.java) { JsonDocument.parse(input) }
            } else {
                val actual = JsonDocument.parse(input)
                assertEquals(name, vector.string("canonical"), actual.canonicalText())
                assertEquals(name, vector.string("sha256"), actual.sha256())
            }
        }
    }

    @Test fun `strict preflight rejects inputs the JCS library alone normalizes`() {
        for (text in listOf("{\"a\":null,\"a\":1}", "{\"a\":01}", "{\"a\":-01}", "{\"a\":1,}", "{\"a\":[1,]}", "{} {}", "[1]", "{\"a\":NaN}")) {
            assertThrows(ProtocolException::class.java) { JsonDocument.parse(text) }
        }
        assertThrows(ProtocolException::class.java) { JsonDocument.parse(byteArrayOf(123, 34, 120, 34, 58, 34, 0xc0.toByte(), 0xaf.toByte(), 34, 125)) }
        assertThrows(ProtocolException::class.java) { JsonDocument.parse(byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + "{}".toByteArray()) }
    }

    @Test fun `parsing and generated objects enforce the same size depth node and Unicode limits`() {
        val deep = "{\"a\":".repeat(33) + "0" + "}".repeat(33)
        assertThrows(ProtocolException::class.java) { JsonDocument.parse(deep) }
        assertThrows(ProtocolException::class.java) { JsonDocument.parse("{\"a\":[" + List(16_384) { "0" }.joinToString(",") + "]}") }
        assertThrows(ProtocolException::class.java) { JsonDocument.parse("{\"a\":\"" + "a".repeat(JsonDocument.MAX_BYTES) + "\"}") }
        assertThrows(ProtocolException::class.java) { JsonDocument.of(jsonObject("a" to "\ud800".json())) }
        assertThrows(ProtocolException::class.java) { JsonDocument.of(jsonObject("a" to JsonNumber(Double.POSITIVE_INFINITY))) }
        val mutable = linkedMapOf<String, JsonValue>("a" to 1L.json())
        val immutable = JsonObject(mutable)
        mutable["a"] = 2L.json()
        assertEquals("{\"a\":1}", JsonDocument.of(immutable).canonicalText())
        assertThrows(UnsupportedOperationException::class.java) { (immutable.fields as MutableMap)["a"] = 3L.json() }
    }

    @Test fun `protocol errors do not include rejected content`() {
        val error = assertThrows(ProtocolException::class.java) { JsonDocument.parse("{\"private-command-secret\":???}") }
        assertEquals("canonical: invalid JSON object", error.message)
        assertNull(error.cause)
    }
}
