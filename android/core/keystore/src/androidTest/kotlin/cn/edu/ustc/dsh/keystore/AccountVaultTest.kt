package cn.edu.ustc.dsh.keystore

import android.app.KeyguardManager
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import cn.edu.ustc.dsh.protocol.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class AccountVaultTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val slot = "test-" + UUID.randomUUID()
    private val vault = AccountVault(context, slot)
    private val account = UUID.randomUUID().toString()
    private val organization = UUID.randomUUID().toString()
    private val deployment = "a".repeat(64)
    private val secret = "fixture-only-access-and-refresh-token-校园".toByteArray(Charsets.UTF_8)
    @Before fun fixture() {
        assumeTrue("explicit secure-lock fixture required", InstrumentationRegistry.getArguments().getString("vaultFixture") == "true")
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        assertTrue("dedicated fixture must have secure lock", keyguard.isDeviceSecure)
        assertFalse("dedicated fixture must be unlocked", keyguard.isDeviceLocked)
    }
    @After fun clean() { vault.clear() }

    @Test fun encryptedRecordSurvivesNewOwnerAndUsesFreshIvWithoutExportableKeyOrPlaintext() {
        assertNull(vault.read())
        vault.save(account, organization, deployment, secret, 0)
        val first = vault.file.baseFile.readBytes()
        assertFalse(first.toString(Charsets.UTF_8).contains("fixture-only-access"))
        AccountVault(context, slot).read()!!.use { record ->
            assertEquals(account, record.accountId); assertEquals(organization, record.organizationId)
            assertEquals(deployment, record.deploymentHash); assertArrayEquals(secret, record.bytes())
        }
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val alias = keys.aliases().toList().single { it.startsWith(vault.keyPrefix) }
        assertNull(keys.getKey(alias, null).encoded)
        assertEquals(2L, vault.save(account, organization, deployment, secret, 1))
        assertEquals(VaultFailure.CONFLICT, assertThrows(VaultException::class.java) { vault.save(account, organization, deployment, secret, 1) }.failure)
        val second = vault.file.baseFile.readBytes()
        assertNotEquals(JsonDocument.parse(first).root.string("iv"), JsonDocument.parse(second).root.string("iv"))
        assertNotEquals(JsonDocument.parse(first).root.string("ciphertext"), JsonDocument.parse(second).root.string("ciphertext"))
        val opened = vault.read()!!; opened.close()
        assertThrows(IllegalStateException::class.java) { opened.bytes() }
    }

    @Test fun tamperingTruncationOversizeAndLostKeyAreRejectedWithoutSilentReplacement() {
        vault.save(account, organization, deployment, secret, 0)
        val original = vault.file.baseFile.readBytes()
        val root = JsonDocument.parse(original).root
        for (mutated in listOf(
            root.with("deployment_sha256" to "b".repeat(64).json()),
            root.with("revision" to 2L.json()),
            root.with("ciphertext" to Contract.base64url(Contract.base64url(root.string("ciphertext")).also { it[0] = (it[0].toInt() xor 1).toByte() }).json()),
            root.with("iv" to "AQ".json()), root.with("extra" to "untrusted".json()),
        )) {
            vault.file.baseFile.writeBytes(JsonDocument.of(mutated).canonicalBytes())
            assertThrows(VaultException::class.java) { vault.read() }
        }
        vault.file.baseFile.writeBytes(original.copyOfRange(0, original.size / 2))
        assertThrows(VaultException::class.java) { vault.read() }
        vault.file.baseFile.writeBytes(ByteArray(JsonDocument.MAX_BYTES + 1))
        assertThrows(VaultException::class.java) { vault.read() }
        vault.file.baseFile.writeBytes(original)
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keys.aliases().toList().filter { it.startsWith(vault.keyPrefix) }.forEach(keys::deleteEntry)
        assertEquals(VaultFailure.KEY_MISSING, assertThrows(VaultException::class.java) { vault.read() }.failure)
        assertEquals(VaultFailure.KEY_MISSING, assertThrows(VaultException::class.java) { vault.save(account, organization, deployment, secret, 0) }.failure)
        assertFalse(keys.aliases().toList().any { it.startsWith(vault.keyPrefix) })
    }

    @Test fun accountReplacementRequiresClearAndAtomicFilesRecoverOnlyTheLastCheckpoint() {
        vault.save(account, organization, deployment, secret, 0)
        assertEquals(VaultFailure.CONFLICT, assertThrows(VaultException::class.java) { vault.save(UUID.randomUUID().toString(), organization, deployment, secret, 1) }.failure)
        val partial = vault.file.startWrite()
        partial.write("incomplete rotating-token checkpoint".toByteArray())
        partial.fd.sync(); partial.close() // Simulate process death without finishWrite/failWrite.
        AccountVault(context, slot).read()!!.use { assertArrayEquals(secret, it.bytes()) }
        vault.clear()
        assertNull(vault.read()); assertFalse(vault.file.baseFile.exists())
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(keys.aliases().toList().any { it.startsWith(vault.keyPrefix) })
        val otherAccount = UUID.randomUUID().toString()
        vault.save(otherAccount, organization, deployment, secret, 0)
        vault.read()!!.use { assertEquals(otherAccount, it.accountId) }
    }
}
