package cn.edu.ustc.dsh.mobile

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.keystore.*
import cn.edu.ustc.dsh.network.RelayException
import cn.edu.ustc.dsh.protocol.RelayScope
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class RelayKeystoreTest {
    @Test fun tlsRelayUsesTheRealNonExportableDeviceProofKeyAndConsumesOneTicket(): Unit = runBlocking {
        assumeTrue("explicit network fixture required", InstrumentationRegistry.getArguments().getString("networkFixture") == "true")
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        AccountFixture(context).use { fixture ->
            val reference = ScopeReference(fixture.accountId, fixture.organizationId)
            PendingKeyLedger(context, fixture.ledgerName).add(reference)
            DeviceKeyStore(context).use { owner ->
                val proof = owner.create(reference.scope(), DeviceKeyPurpose.PROOF, 1)
                val ticket = fixture.readApi(proof).readTicket("55555555-5555-4555-8555-555555555555", fixture.deviceId,
                    RelayScope(listOf("session.read"), emptyList(), listOf("66666666-6666-4666-8666-666666666666")))
                withTimeout(15_000) { ticket.connect() }.use { connection ->
                    assertEquals(fixture.deviceId, connection.identity.deviceId)
                    assertEquals(7L, connection.identity.grantVersion)
                    assertTrue(fixture.relayProofReceived)
                    assertTrue(fixture.failure.get() == null)
                }
                assertEquals("ticket.invalid", assertThrows(RelayException::class.java) { runBlocking { ticket.connect() } }.code)
            }
        }
    }
}
