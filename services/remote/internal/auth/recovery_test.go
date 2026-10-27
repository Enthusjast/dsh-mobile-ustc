package auth

import "testing"

func TestRecoveryEpochSeparatesProofStateAndCutoffDoesNotUseClockSkew(t *testing.T) {
	keys := newTestKeys(t)
	base, err := ProofScope("https://id.example.edu", "urn:test", "https://api.example.edu")
	if err != nil {
		t.Fatal(err)
	}
	first, err := ProofScopeInEpoch(base, "aaaaaaaa-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ProofScopeInEpoch(base, "bbbbbbbb-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := ProofScopeInEpoch(base, OriginalDatabaseEpoch)
	if err != nil || legacy != base || first == base || first == second {
		t.Fatal("recovery reused old proof scope", err)
	}
	if _, err := ProofScopeInEpoch(base, "PRIVATE_UNTRUSTED_EPOCH"); err == nil {
		t.Fatal("invalid recovery epoch accepted")
	}
	keys.verifier.minimumIssuedAt = keys.now
	older := keys.token(t, func(claims map[string]any) { claims["iat"] = keys.now.Unix() - 1 })
	if _, err := keys.verifier.VerifyAccessToken(t.Context(), older); err == nil {
		t.Fatal("clock skew revived pre-cutoff access token")
	}
	if _, err := keys.verifier.VerifyAccessToken(t.Context(), keys.token(t, nil)); err != nil {
		t.Fatal("fresh token rejected by cutoff", err)
	}
}
