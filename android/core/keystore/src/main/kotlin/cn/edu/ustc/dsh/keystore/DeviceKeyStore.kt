package cn.edu.ustc.dsh.keystore

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.crypto.impl.ECDSA
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

enum class DeviceCryptoFailure {
    LOCK_REQUIRED, BIOMETRIC_REQUIRED, HARDWARE_REQUIRED, KEY_EXISTS, KEY_MISSING, KEY_INVALIDATED,
    AUTHENTICATION_REQUIRED, CANCELLED, WRONG_KEY, BUSY, UNAVAILABLE,
}
class DeviceCryptoException(val failure: DeviceCryptoFailure) : IllegalStateException("device crypto: ${failure.name.lowercase()}")

/** Local random account ID plus the verified organization ID; never an email. */
class DeviceKeyScope(accountId: String, organizationId: String) {
    internal val digest: String
    init {
        Contract.uuid(accountId); Contract.uuid(organizationId)
        digest = sha256("dsh-mobile-ustc/device-key-scope/v1\u0000$accountId\u0000$organizationId".toByteArray(Charsets.UTF_8))
    }
}

enum class DeviceKeyPurpose(internal val wire: String) { PROOF("proof"), APPROVAL("approval") }

/** Own one instance in the account lifecycle. Call close before logout/revocation. */
class DeviceKeyStore(context: Context) : AutoCloseable {
    private val appContext = context.applicationContext
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private val handles = mutableSetOf<DeviceKeyHandle>()
    private var closed = false

    /** Explicit enrollment only: missing/invalidated keys are never silently replaced. */
    @Synchronized
    fun create(scope: DeviceKeyScope, purpose: DeviceKeyPurpose, version: Long, requireHardware: Boolean = false): DeviceKeyHandle = deviceCheck {
        ensureOpen()
        val alias = alias(scope, purpose, version)
        if (store.containsAlias(alias)) throw DeviceCryptoException(DeviceCryptoFailure.KEY_EXISTS)
        if (purpose == DeviceKeyPurpose.APPROVAL) {
            if (!appContext.getSystemService(KeyguardManager::class.java).isDeviceSecure) throw DeviceCryptoException(DeviceCryptoFailure.LOCK_REQUIRED)
            if (BiometricManager.from(appContext).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) != BiometricManager.BIOMETRIC_SUCCESS) throw DeviceCryptoException(DeviceCryptoFailure.BIOMETRIC_REQUIRED)
        }
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(purpose == DeviceKeyPurpose.APPROVAL)
        if (purpose == DeviceKeyPurpose.APPROVAL) {
            if (Build.VERSION.SDK_INT >= 30) builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            builder.setInvalidatedByBiometricEnrollment(true)
        }
        try {
            KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").apply { initialize(builder.build()) }.generateKeyPair()
            load(scope, purpose, version, requireHardware)
        } catch (error: Exception) {
            // Remove only this newly created enrollment attempt, never an existing key.
            store.deleteEntry(alias)
            throw error
        }
    }

    @Synchronized
    fun load(scope: DeviceKeyScope, purpose: DeviceKeyPurpose, version: Long, requireHardware: Boolean = false): DeviceKeyHandle = deviceCheck {
        ensureOpen()
        handles.removeAll { it.isClosed }
        if (handles.size >= 64) throw DeviceCryptoException(DeviceCryptoFailure.BUSY)
        val alias = alias(scope, purpose, version)
        val privateKey = store.getKey(alias, null) as? PrivateKey ?: throw DeviceCryptoException(DeviceCryptoFailure.KEY_MISSING)
        val publicKey = store.getCertificate(alias)?.publicKey as? ECPublicKey ?: throw DeviceCryptoException(DeviceCryptoFailure.KEY_MISSING)
        val info = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").getKeySpec(privateKey, KeyInfo::class.java)
        validate(info, purpose, requireHardware)
        val key = ECKey.Builder(Curve.P_256, publicKey).build()
        val jwk = JsonDocument.parse(key.toPublicJWK().toJSONString()).root
        DeviceKeyHandle(alias, purpose, jwk, key.computeThumbprint().toString(), privateKey, publicKey).also { handles += it }
    }

    /** Deleting a key is local cleanup; server-side device revocation is separate. */
    @Synchronized
    fun delete(scope: DeviceKeyScope, purpose: DeviceKeyPurpose, version: Long) = deviceCheck {
        ensureOpen()
        val alias = alias(scope, purpose, version)
        handles.filter { it.alias == alias }.forEach { it.close() }
        handles.removeAll { it.alias == alias }
        store.deleteEntry(alias)
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        handles.forEach { it.close() }; handles.clear()
    }

    private fun ensureOpen() { if (closed) throw DeviceCryptoException(DeviceCryptoFailure.CANCELLED) }
    private fun alias(scope: DeviceKeyScope, purpose: DeviceKeyPurpose, version: Long): String {
        if (version !in 1..MAX_SAFE_INTEGER) throw DeviceCryptoException(DeviceCryptoFailure.UNAVAILABLE)
        return "dsh/device/v1/${scope.digest}/${purpose.wire}/$version"
    }
    private fun validate(info: KeyInfo, purpose: DeviceKeyPurpose, requireHardware: Boolean) {
        @Suppress("DEPRECATION")
        val hardware = if (Build.VERSION.SDK_INT >= 31) info.securityLevel in setOf(KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT, KeyProperties.SECURITY_LEVEL_STRONGBOX) else info.isInsideSecureHardware
        if (requireHardware && (!hardware || (purpose == DeviceKeyPurpose.APPROVAL && !info.isUserAuthenticationRequirementEnforcedBySecureHardware))) throw DeviceCryptoException(DeviceCryptoFailure.HARDWARE_REQUIRED)
        @Suppress("DEPRECATION")
        val perUse = info.userAuthenticationValidityDurationSeconds == -1 || (Build.VERSION.SDK_INT >= 30 && info.userAuthenticationValidityDurationSeconds == 0)
        if (info.keySize != 256 || info.origin != KeyProperties.ORIGIN_GENERATED || info.digests.toSet() != setOf(KeyProperties.DIGEST_SHA256) ||
            info.purposes != (KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY) || info.isUserAuthenticationRequired != (purpose == DeviceKeyPurpose.APPROVAL)) throw DeviceCryptoException(DeviceCryptoFailure.UNAVAILABLE)
        if (purpose == DeviceKeyPurpose.APPROVAL && (!perUse || !info.isInvalidatedByBiometricEnrollment ||
            (Build.VERSION.SDK_INT >= 30 && info.userAuthenticationType != KeyProperties.AUTH_BIOMETRIC_STRONG))) throw DeviceCryptoException(DeviceCryptoFailure.UNAVAILABLE)
    }
}

class DeviceKeyHandle internal constructor(
    internal val alias: String,
    val purpose: DeviceKeyPurpose,
    val publicJwk: JsonObject,
    val thumbprint: String,
    private val privateKey: PrivateKey,
    private val publicKey: ECPublicKey,
) : AutoCloseable {
    @Volatile private var closed = false
    @Volatile private var operation: AuthenticatedKeyOperation<*>? = null
    internal val isClosed: Boolean get() = closed

    /** Only the independent proof key can sign HTTP/WSS proof input without UI. */
    @Synchronized
    fun signProof(signingInput: ByteArray): ByteArray = deviceCheck {
        ensureOpen()
        if (purpose != DeviceKeyPurpose.PROOF || signingInput.size !in 1..16 * 1024) throw DeviceCryptoException(DeviceCryptoFailure.WRONG_KEY)
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey); update(signingInput.copyOf()) }.sign()
        ECDSA.transcodeSignatureToConcat(signature, 64)
    }

    fun proofSigner(): DeviceProofSigner {
        if (purpose != DeviceKeyPurpose.PROOF) throw DeviceCryptoException(DeviceCryptoFailure.WRONG_KEY)
        return object : DeviceProofSigner {
            override val publicKey = PublicProofKey(publicJwk)
            override fun signJose(signingInput: ByteArray): ByteArray = signProof(signingInput)
        }
    }

    /** The app shows full context, then authenticates this exact operation with BiometricPrompt. */
    @Synchronized
    fun beginApproval(request: PreparedApprovalSignature): ApprovalKeyOperation = beginAuthenticated(request)

    fun beginRegistration(request: PreparedDeviceRegistration): AuthenticatedKeyOperation<DeviceRegistrationProof> = beginAuthenticated(request)

    @Synchronized
    private fun <T> beginAuthenticated(request: PreparedUserSignature<T>): AuthenticatedKeyOperation<T> = deviceCheck {
        ensureOpen()
        if (purpose != DeviceKeyPurpose.APPROVAL || request.keyThumbprint != thumbprint) throw DeviceCryptoException(DeviceCryptoFailure.WRONG_KEY)
        if (operation != null) throw DeviceCryptoException(DeviceCryptoFailure.BUSY)
        val signature = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey) }
        AuthenticatedKeyOperation(request, signature, { !closed }) {
            // Reinitialization aborts an unconsumed AndroidKeyStore operation;
            // a retained old CryptoObject can no longer produce a signature.
            runCatching { signature.initVerify(publicKey) }
            operation = null
        }.also { operation = it }
    }

    @Synchronized
    override fun close() { closed = true; operation?.close(); operation = null }

    private fun ensureOpen() { if (closed) throw DeviceCryptoException(DeviceCryptoFailure.CANCELLED) }
}

typealias ApprovalKeyOperation = AuthenticatedKeyOperation<SignedApprovalDecision>

class AuthenticatedKeyOperation<T> internal constructor(
    private val request: PreparedUserSignature<T>,
    private val signature: Signature,
    private val ownerActive: () -> Boolean,
    private val onEnd: () -> Unit,
) : AutoCloseable {
    private var ended = false
    val cryptoObject: BiometricPrompt.CryptoObject get() = synchronized(this) {
        if (ended || !ownerActive()) throw DeviceCryptoException(DeviceCryptoFailure.CANCELLED)
        BiometricPrompt.CryptoObject(signature)
    }

    /** Accept only the same crypto object returned by the successful platform prompt. */
    @Synchronized
    fun finish(result: BiometricPrompt.AuthenticationResult): T = deviceCheck {
        if (ended || !ownerActive()) throw DeviceCryptoException(DeviceCryptoFailure.CANCELLED)
        ended = true
        try {
            if (result.cryptoObject?.signature !== signature) throw DeviceCryptoException(DeviceCryptoFailure.WRONG_KEY)
            signature.update(request.signingInput())
            val der = signature.sign()
            if (!ownerActive()) throw DeviceCryptoException(DeviceCryptoFailure.CANCELLED)
            request.finishDerSignature(der, System.currentTimeMillis())
        } finally { request.cancel(); onEnd() }
    }

    @Synchronized
    override fun close() { if (!ended) { ended = true; request.cancel(); onEnd() } }
}

private inline fun <T> deviceCheck(block: () -> T): T = try { block() } catch (error: DeviceCryptoException) { throw error }
catch (_: KeyPermanentlyInvalidatedException) { throw DeviceCryptoException(DeviceCryptoFailure.KEY_INVALIDATED) }
catch (_: UserNotAuthenticatedException) { throw DeviceCryptoException(DeviceCryptoFailure.AUTHENTICATION_REQUIRED) }
catch (_: Exception) { throw DeviceCryptoException(DeviceCryptoFailure.UNAVAILABLE) }
