package cn.edu.ustc.dsh.auth

import cn.edu.ustc.dsh.crypto.*
import cn.edu.ustc.dsh.protocol.*
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.RSASSASigner
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.gen.ECKeyGenerator
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.junit.Assert.*
import org.junit.Test
import java.net.URLEncoder

class LoginTest {
    private val now = 1_792_838_400_000L
    private val configuration = JsonDocument.parse("""{
      "issuer":"https://id.example.edu/oidc", "client_id":"mobile", "redirect_uri":"cn.edu.ustc.dsh.mobile:/oauth2redirect",
      "resource":"urn:dsh-remote", "audience":"urn:dsh-remote", "remote_origin":"https://remote.example.edu",
      "organization_id":"11111111-1111-4111-8111-111111111111", "scopes":["openid","remote.access"],
      "endpoint_origins":["https://id.example.edu"], "signing_algorithms":["ES256","RS256"]
    }""")
    private val discovery = JsonDocument.parse("""{
      "issuer":"https://id.example.edu/oidc", "authorization_endpoint":"https://id.example.edu/authorize",
      "token_endpoint":"https://id.example.edu/token", "jwks_uri":"https://id.example.edu/jwks",
      "response_types_supported":["code"], "code_challenge_methods_supported":["S256"], "grant_types_supported":["authorization_code"],
      "token_endpoint_auth_methods_supported":["none"], "dpop_signing_alg_values_supported":["ES256"],
      "id_token_signing_alg_values_supported":["RS256","ES256"], "authorization_response_iss_parameter_supported":true
    }""")
    private fun config() = LoginConfiguration.parse(configuration.canonicalBytes())
    private fun pending() = PendingLogin(OidcDiscovery.parse(discovery.canonicalBytes(), config()), "A".repeat(43), now)
    private fun callback(pending: PendingLogin, code: String = "code-opaque"): String = LoginConfiguration.REDIRECT_URI + "?code=$code&state=${pending.state}&iss=" + URLEncoder.encode(config().issuer, "UTF-8")

    @Test fun pkceUsesFreshRandomStateNonceAndS256AndAcceptsOneExactCallback() {
        val first = pending(); val second = pending()
        assertNotEquals(first.state, second.state); assertNotEquals(first.nonce, second.nonce)
        assertEquals(32, Contract.base64url(first.state).size)
        assertEquals("S256", first.authorizationParameters()["code_challenge_method"])
        val exchange = first.acceptCallback(callback(first), now + 1000)
        val form = exchange.form()
        assertEquals("authorization_code", form["grant_type"])
        assertEquals(config().resource, form["resource"])
        assertEquals(first.codeChallenge, Contract.base64url(java.security.MessageDigest.getInstance("SHA-256").digest(form["code_verifier"]!!.toByteArray(Charsets.US_ASCII))))
        assertThrows(LoginException::class.java) { first.acceptCallback(callback(first), now + 1000) }
        for (wrong in listOf(
            callback(second).replace("oauth2redirect", "other"), callback(second).replace(second.state, first.state),
            callback(second) + "&state=${second.state}", callback(second) + "&%73tate=${second.state}",
            callback(second) + "#fragment", callback(second).replace("https%3A%2F%2Fid.example.edu%2Foidc", "https%3A%2F%2Fevil.example.edu"),
        )) assertThrows(LoginException::class.java) { second.acceptCallback(wrong, now + 1000) }
        assertNotNull(second.acceptCallback(callback(second), now + 1000))
        val expired = pending()
        assertEquals(LoginFailure.EXPIRED, assertThrows(LoginException::class.java) { expired.acceptCallback(callback(expired), now + 600_001) }.failure)
        assertThrows(LoginException::class.java) { expired.acceptCallback(callback(expired), now + 1) }
        val cancelled = pending(); cancelled.cancel()
        assertThrows(LoginException::class.java) { cancelled.acceptCallback(callback(cancelled), now) }
    }

    @Test fun discoveryAndTrustedConfigurationCannotSelectInsecureOrUntrustedEndpoints() {
        for (changed in listOf(
            discovery.root.with("issuer" to "https://other.example.edu".json()),
            discovery.root.with("token_endpoint" to "http://id.example.edu/token".json()),
            discovery.root.with("jwks_uri" to "https://evil.example.edu/jwks".json()),
            discovery.root.with("authorization_endpoint" to "https://user@id.example.edu/authorize".json()),
            discovery.root.with("authorization_endpoint" to "https://id.example.edu/authorize?code_challenge_method=plain".json()),
            discovery.root.with("token_endpoint" to "https://id.example.edu/token?client_id=other".json()),
            discovery.root.with("code_challenge_methods_supported" to JsonArray(listOf("plain".json()))),
            discovery.root.with("dpop_signing_alg_values_supported" to JsonArray(listOf("none".json()))),
            discovery.root.with("token_endpoint_auth_methods_supported" to JsonArray(listOf("client_secret_basic".json()))),
        )) assertThrows(LoginException::class.java) { OidcDiscovery.parse(JsonDocument.of(changed).canonicalBytes(), config()) }
        for (changed in listOf(
            configuration.root.with("redirect_uri" to "evil:/callback".json()),
            configuration.root.with("remote_origin" to "https://remote.example.edu/path".json()),
            configuration.root.with("signing_algorithms" to JsonArray(listOf("HS256".json()))),
        )) assertThrows(LoginException::class.java) { LoginConfiguration.parse(JsonDocument.of(changed).canonicalBytes()) }
    }

    private fun jwt(header: JsonObject, claims: JsonObject, signer: (JWSHeader, ByteArray) -> String): String {
        val input = "${Contract.base64url(JsonDocument.of(header).canonicalBytes())}.${Contract.base64url(JsonDocument.of(claims).canonicalBytes())}"
        return "$input.${signer(JWSHeader.parse(JsonDocument.of(header).canonicalText()), input.toByteArray(Charsets.US_ASCII))}"
    }

    @Test fun signedOidcAndAccessTokensRequireExactIdentityNonceAudiencePurposeScopeAndProofKey() {
        for (algorithm in listOf("ES256", "RS256")) {
            val ec = ECKeyGenerator(Curve.P_256).keyID("issuer-ec").generate()
            val rsa = RSAKeyGenerator(2048).keyID("issuer-rsa").generate()
            val selected = if (algorithm == "ES256") ec else rsa
            val signer = if (algorithm == "ES256") ECDSASigner(ec) else RSASSASigner(rsa)
            val publicJwk = JsonDocument.parse(selected.toPublicJWK().toJSONString()).root
            val keys = IssuerKeys.parse(JsonDocument.of(jsonObject("keys" to JsonArray(listOf(publicJwk)))).canonicalBytes())
            val login = pending(); val exchange = login.acceptCallback(callback(login), now + 1)
            val common = jsonObject("iss" to config().issuer.json(), "sub" to "school-user".json(), "iat" to (now / 1000).json(), "exp" to (now / 1000 + 300).json())
            val access = common.with("aud" to config().audience.json(), "client_id" to config().clientId.json(), "jti" to "access-token-id".json(),
                "scope" to "remote.access".json(), "cnf" to jsonObject("jkt" to login.proofKeyThumbprint.json()))
            val id = common.with("aud" to config().clientId.json(), "nonce" to login.nonce.json())
            fun signed(claims: JsonObject, type: String) = jwt(jsonObject("alg" to algorithm.json(), "kid" to selected.keyID.json(), "typ" to type.json()), claims) { header, input -> signer.sign(header, input).toString() }
            fun response(idClaims: JsonObject = id, accessClaims: JsonObject = access, tokenType: String = "DPoP", idType: String = "JWT", accessType: String = "at+jwt"): ByteArray = JsonDocument.of(jsonObject(
                "access_token" to signed(accessClaims, accessType).json(), "id_token" to signed(idClaims, idType).json(), "token_type" to tokenType.json(), "expires_in" to 300L.json(), "refresh_token" to "refresh-secret".json(),
            )).canonicalBytes()
            val session = TokenVerifier.authorizationCodeResponse(response(), exchange, keys, now + 1000)
            assertEquals("school-user", session.subject)
            assertEquals(login.proofKeyThumbprint, session.proofKeyThumbprint)
            assertNotNull(session.accessTokenForRequest(now + 2000))
            assertThrows(LoginException::class.java) { session.accessTokenForRequest(now + 301_000) }
            val wrongIds = listOf(id.with("nonce" to "wrong".json()), id.with("iss" to "https://evil.example.edu".json()), id.with("aud" to "another-client".json()),
                id.with("sub" to "other-user".json()), id.with("exp" to (now / 1000).json()), id.with("iat" to (now / 1000 + 32).json()),
                id.with("aud" to JsonArray(listOf(config().clientId.json(), "another".json()))), id.with("azp" to "other".json()),
                id.with("at_hash" to "wrong".json()), id.with("c_hash" to "wrong".json()))
            wrongIds.forEach { assertThrows(LoginException::class.java) { TokenVerifier.authorizationCodeResponse(response(idClaims = it), exchange, keys, now + 1000) } }
            val wrongAccess = listOf(access.with("cnf" to jsonObject("jkt" to "B".repeat(43).json())), access.with("aud" to "desktop-model".json()),
                access.with("client_id" to "desktop".json()), access.with("scope" to "model.use".json()), access.with("sub" to "another-user".json()),
                access.with("nbf" to (now / 1000 + 32).json()), access.with("exp" to (now / 1000 + 3601).json()))
            wrongAccess.forEach { assertThrows(LoginException::class.java) { TokenVerifier.authorizationCodeResponse(response(accessClaims = it), exchange, keys, now + 1000) } }
            assertThrows(LoginException::class.java) { TokenVerifier.authorizationCodeResponse(response(tokenType = "Bearer"), exchange, keys, now + 1000) }
            assertThrows(LoginException::class.java) { TokenVerifier.authorizationCodeResponse(response(accessType = "JWT"), exchange, keys, now + 1000) }
            assertThrows(LoginException::class.java) { TokenVerifier.authorizationCodeResponse(response(idType = "at+jwt"), exchange, keys, now + 1000) }
            val duplicate = "{\"keys\":[${JsonDocument.of(publicJwk).canonicalText()},${JsonDocument.of(publicJwk).canonicalText()}]}"
            assertThrows(LoginException::class.java) { TokenVerifier.authorizationCodeResponse(response(), exchange, IssuerKeys.parse(duplicate.toByteArray()), now + 1000) }
        }
    }
}
