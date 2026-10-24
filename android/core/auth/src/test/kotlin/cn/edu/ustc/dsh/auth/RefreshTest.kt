package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import org.junit.Assert.*
import org.junit.Test

class RefreshTest {
    private val now = 1_792_838_400_000L
    private val refreshAt = now + 301_000
    private val config = LoginConfiguration.parse("""{
      "issuer":"https://id.example.edu", "client_id":"mobile", "redirect_uri":"cn.edu.ustc.dsh.mobile:/oauth2redirect",
      "resource":"urn:dsh-remote", "audience":"urn:dsh-remote", "remote_origin":"https://remote.example.edu",
      "organization_id":"11111111-1111-4111-8111-111111111111", "scopes":["openid","remote.access"],
      "endpoint_origins":["https://id.example.edu"], "signing_algorithms":["ES256"]
    }""".toByteArray())
    private val discovery = OidcDiscovery.parse("""{
      "issuer":"https://id.example.edu", "authorization_endpoint":"https://id.example.edu/authorize",
      "token_endpoint":"https://id.example.edu/token", "jwks_uri":"https://id.example.edu/jwks",
      "response_types_supported":["code"], "id_token_signing_alg_values_supported":["ES256"]
    }""".toByteArray(), config)
    private val oldKey = ECKeyGenerator(Curve.P_256).keyID("original-issuer-key").generate()
    private val newKey = ECKeyGenerator(Curve.P_256).keyID("rotated-issuer-key").generate()
    private fun keys(key: ECKey) = IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(JsonDocument.parse(key.toPublicJWK().toJSONString()).root)))).canonicalBytes())
    private fun jwt(claims: JsonObject, type: String, key: ECKey) = JWSObject(JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.keyID).type(JOSEObjectType(type)).build(), Payload(JsonDocument.of(claims).canonicalText())).apply { sign(ECDSASigner(key)) }.serialize()
    private val login = PendingLogin(discovery, "A".repeat(43), now)
    private fun common(at: Long) = jsonObject("iss" to config.issuer.json(), "sub" to "school-user".json(), "iat" to (at / 1000).json(), "exp" to (at / 1000 + 300).json())
    private fun access(at: Long) = common(at).with("aud" to config.audience.json(), "client_id" to config.clientId.json(), "jti" to "fresh-access-token".json(), "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to login.proofKeyThumbprint.json()))
    private fun identity(at: Long) = common(at).with("aud" to JsonArray(listOf(config.clientId.json(), "trusted-extra-audience".json())), "azp" to config.clientId.json(), "auth_time" to (now / 1000 - 10).json())
    private fun original(): LoginSession {
        val exchange = login.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${login.state}&code=opaque-code", now + 1)
        val response = jsonObject("token_type" to "DPoP".json(), "expires_in" to 300L.json(), "access_token" to jwt(access(now), "at+jwt", oldKey).json(),
            "id_token" to jwt(identity(now).with("nonce" to login.nonce.json()), "JWT", oldKey).json(), "refresh_token" to "original-refresh-secret".json())
        return TokenVerifier.authorizationCodeResponse(JsonDocument.of(response).canonicalBytes(), exchange, keys(oldKey), now + 1000)
    }
    private fun response(at: Long = refreshAt, claims: JsonObject = access(at), id: JsonObject? = null, type: String = "DPoP", idType: String = "JWT"): JsonObject {
        var result = jsonObject("token_type" to type.json(), "expires_in" to 300L.json(), "access_token" to jwt(claims, "at+jwt", newKey).json(), "refresh_token" to "rotated-refresh-secret".json())
        if (id != null) result = result.with("id_token" to jwt(id, idType, newKey).json())
        return result
    }
    private fun refresh(raw: JsonObject, previous: LoginSession, at: Long = refreshAt) = TokenVerifier.refreshResponse(JsonDocument.of(raw).canonicalBytes(), previous, config, keys(newKey), at, at + 1000)

    @Test fun decryptedCredentialsCannotCallResourcesUntilSignedClaimsAreReverified() {
        val previous = original()
        val stored = previous.authenticatedStorageBytes()
        val restored = StoredLogin.parseAuthenticated(stored, config, previous.proofKeyThumbprint, now + 2000)
        assertEquals(LoginFailure.IDENTITY, assertThrows(LoginException::class.java) { restored.accessTokenForRequest(now + 2000) }.failure)
        assertNotNull(TokenVerifier.revalidateStored(restored, config, keys(oldKey), now + 2000).accessTokenForRequest(now + 2000))
        assertThrows(LoginException::class.java) { TokenVerifier.revalidateStored(restored, config, keys(newKey), now + 2000) }
        assertThrows(LoginException::class.java) { StoredLogin.parseAuthenticated(stored, config, "B".repeat(43), now + 2000) }
        assertThrows(LoginException::class.java) { StoredLogin.parseAuthenticated(stored, config, previous.proofKeyThumbprint, now) }
        val root = JsonDocument.parse(stored).root
        for (bad in listOf(root.with("deployment_sha256" to "b".repeat(64).json()), root.with("identity" to root.obj("identity").with("nonce" to "invalid".json())), root.with("refresh_token" to "bad\nsecret".json()))) {
            assertThrows(LoginException::class.java) { StoredLogin.parseAuthenticated(JsonDocument.of(bad).canonicalBytes(), config, previous.proofKeyThumbprint, now + 2000) }
        }
        val extended = StoredLogin.parseAuthenticated(JsonDocument.of(root.with("access_expires_at" to (now + 600_000).json())).canonicalBytes(), config, previous.proofKeyThumbprint, now + 2000)
        assertThrows(LoginException::class.java) { TokenVerifier.revalidateStored(extended, config, keys(oldKey), now + 2000) }
    }

    @Test fun expiredAccessCanRefreshWithoutIdTokenAcrossIssuerKeyRotation() {
        val previous = original()
        val restored = StoredLogin.parseAuthenticated(previous.authenticatedStorageBytes(), config, previous.proofKeyThumbprint, refreshAt)
        val refreshed = refresh(response(), restored)
        assertEquals("school-user", refreshed.subject); assertEquals("rotated-refresh-secret", refreshed.consumeRefreshTokenForRequest())
        assertEquals(LoginFailure.REAUTHENTICATION, assertThrows(LoginException::class.java) { refreshed.consumeRefreshTokenForRequest() }.failure)
        assertNotNull(refreshed.accessTokenForRequest(refreshAt + 1000))
        assertThrows(LoginException::class.java) { refreshed.accessTokenForRequest(refreshAt) }
        val noRotation = response().let { JsonObject(it.fields - "refresh_token") }
        assertEquals("original-refresh-secret", refresh(noRotation, restored).consumeRefreshTokenForRequest())
        assertNotNull(refresh(response().with("scope" to "remote.access".json()), restored))
    }

    @Test fun refreshedIdTokenPreservesAudienceSubjectOriginalAuthTimeAndOptionalNonce() {
        val previous = original()
        assertNotNull(refresh(response(id = identity(refreshAt)), previous))
        assertNotNull(refresh(response(id = identity(refreshAt).with("nonce" to login.nonce.json())), previous))
        val wrong = listOf(
            identity(refreshAt).with("sub" to "other-user".json()), identity(refreshAt).with("iss" to "https://other.example.edu".json()),
            identity(refreshAt).with("aud" to config.clientId.json()), identity(refreshAt).with("azp" to "other-client".json()),
            JsonObject(identity(refreshAt).fields - "azp"), identity(refreshAt).with("auth_time" to (refreshAt / 1000).json()),
            identity(refreshAt).with("nonce" to "wrong".json()), identity(refreshAt).with("at_hash" to "wrong".json()),
            identity(refreshAt).with("c_hash" to "old-code-hash".json()), identity(refreshAt).with("exp" to (refreshAt / 1000).json()),
        )
        wrong.forEach { assertThrows(LoginException::class.java) { refresh(response(id = it), previous) } }
        assertThrows(LoginException::class.java) { refresh(response(id = identity(refreshAt), idType = "at+jwt"), previous) }
        val refreshed = refresh(response(id = identity(refreshAt)), previous)
        val stored = StoredLogin.parseAuthenticated(refreshed.authenticatedStorageBytes(), config, previous.proofKeyThumbprint, refreshAt + 2000)
        assertNotNull(refresh(response(at = refreshAt + 301_000, id = identity(refreshAt + 301_000)), stored, refreshAt + 301_000))
    }

    @Test fun refreshCannotDowngradeExpandScopeChangeBindingOrIgnoreClockRollback() {
        val previous = original()
        assertThrows(LoginException::class.java) { refresh(response(type = "Bearer"), previous) }
        for (claims in listOf(
            access(refreshAt).with("aud" to "model-resource".json()), access(refreshAt).with("sub" to "different-user".json()),
            access(refreshAt).with("client_id" to "desktop-client".json()), access(refreshAt).with("cnf" to jsonObject("jkt" to "B".repeat(43).json())),
            access(refreshAt).with("scope" to "remote.access remote.admin".json()), access(refreshAt).with("scope" to "model.use".json()),
            access(refreshAt).with("jti" to "".json()), access(refreshAt).with("iat" to (refreshAt / 1000 - 31).json()),
            access(refreshAt).with("iat" to (refreshAt / 1000 + 32).json()), access(refreshAt).with("exp" to (refreshAt / 1000 + 3601).json()),
        )) assertThrows(LoginException::class.java) { refresh(response(claims = claims), previous) }
        assertThrows(LoginException::class.java) { refresh(response().with("scope" to "openid remote.access remote.admin".json()), previous) }
        assertThrows(LoginException::class.java) { refresh(response().with("expires_in" to 0L.json()), previous) }
        assertThrows(LoginException::class.java) { TokenVerifier.refreshResponse(JsonDocument.of(response()).canonicalBytes(), previous, config, keys(newKey), refreshAt, refreshAt - 1) }
    }

    @Test fun checkpointsPreserveUnknownEffectsAndFenceRotatingCredentialsAcrossRestoration() {
        val session = original()
        val localId = "22222222-2222-4222-8222-222222222222"
        val userId = "33333333-3333-4333-8333-333333333333"
        val pending = AccountCheckpoint.create(localId, config, userId, session, now + 2000)
        assertThrows(LoginException::class.java) { pending.beginEnrollment("校园手机", now + 2000) }
        val withKey = pending.withApprovalKey("B".repeat(42) + "A", now + 2001)
        val posting = withKey.beginEnrollment("校园手机", now + 2002)
        val recovered = AccountCheckpoint.parseAuthenticated(posting.authenticatedStorageBytes(), config, session.proofKeyThumbprint, now + 3000, localId)
        assertEquals(EnrollmentCheckpoint.REGISTERING, recovered.enrollment)
        assertEquals("校园手机", recovered.deviceName)
        assertThrows(LoginException::class.java) { recovered.beginEnrollment("校园手机", now + 3000) }
        val verified = TokenVerifier.revalidateStored(recovered.session, config, keys(oldKey), now + 3000)
        val ready = recovered.revalidated(verified, userId, now + 3000).enrollmentNotFound(now + 3000)
        assertThrows(LoginException::class.java) { ready.beginEnrollment("改名会改变请求内容", now + 3000) }
        val active = ready.beginEnrollment("校园手机", now + 3000).deviceAccepted("44444444-4444-4444-8444-444444444444", 1, now + 4000)
        assertThrows(LoginException::class.java) { active.beginRefresh(now + 5000).authorized(session, userId, now + 6000) }
        assertThrows(LoginException::class.java) { active.enrollmentNotFound(now + 5000) }
        assertThrows(LoginException::class.java) { active.deviceAccepted("55555555-5555-4555-8555-555555555555", 1, now + 5000) }
        val refreshing = active.beginRefresh(refreshAt)
        val restored = AccountCheckpoint.parseAuthenticated(refreshing.authenticatedStorageBytes(), config, session.proofKeyThumbprint, refreshAt + 1000, localId)
        assertEquals(RefreshCheckpoint.REFRESHING, restored.refresh)
        assertEquals(active.deviceId, restored.deviceId)
        assertThrows(LoginException::class.java) { restored.beginRefresh(refreshAt + 1000) }
        assertThrows(LoginException::class.java) { restored.revalidated(verified, userId, refreshAt + 1000) }
        assertThrows(LoginException::class.java) { restored.authorized(verified, userId, refreshAt + 1000) }
        assertThrows(LoginException::class.java) { restored.refreshed(verified, refreshAt + 1000) }
        val authenticated = refresh(response(), restored.session)
        val rotated = restored.refreshed(authenticated, refreshAt + 1000)
        assertEquals(RefreshCheckpoint.READY, rotated.refresh)
        assertEquals(active.deviceId, rotated.deviceId)
        assertThrows(LoginException::class.java) { restored.authorized(authenticated, localId, refreshAt + 1000) }
        assertThrows(LoginException::class.java) { AccountCheckpoint.parseAuthenticated(active.authenticatedStorageBytes(), config, session.proofKeyThumbprint, now + 5000, userId) }
        assertThrows(LoginException::class.java) { active.withApprovalKey("C".repeat(42) + "A", now + 5000) }
        val authorizationAt = refreshAt + 2000
        val newLogin = PendingLogin(discovery, session.proofKeyThumbprint, authorizationAt)
        val exchange = newLogin.acceptCallback(LoginConfiguration.REDIRECT_URI + "?state=${newLogin.state}&code=new-browser-code", authorizationAt + 1)
        val browserResponse = jsonObject("token_type" to "DPoP".json(), "expires_in" to 300L.json(),
            "access_token" to jwt(access(authorizationAt), "at+jwt", newKey).json(), "refresh_token" to "new-browser-refresh-secret".json(),
            "id_token" to jwt(identity(authorizationAt).with("nonce" to newLogin.nonce.json()), "JWT", newKey).json())
        val reauthorized = TokenVerifier.authorizationCodeResponse(JsonDocument.of(browserResponse).canonicalBytes(), exchange, keys(newKey), authorizationAt + 1000)
        val resumed = restored.authorized(reauthorized, userId, authorizationAt + 1000)
        assertEquals(RefreshCheckpoint.READY, resumed.refresh)
        assertEquals(active.deviceId, resumed.deviceId)
    }
}
