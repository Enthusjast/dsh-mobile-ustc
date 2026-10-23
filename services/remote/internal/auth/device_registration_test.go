package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestDeviceRegistrationProofBindsApprovalKeyToCurrentDPoPRequest(t *testing.T) {
	keys := newTestKeys(t)
	approvalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approvalJWK := testProofJWK(approvalKey)
	approvalJSON, err := json.Marshal(approvalJWK)
	if err != nil {
		t.Fatal(err)
	}
	approvalJKT, err := JWKThumbprint(approvalJWK)
	if err != nil {
		t.Fatal(err)
	}
	principal := Principal{Issuer: keys.issuer, Subject: "user-ustc-123", ProofJTI: "dpop-proof-current-0001"}
	deviceName := "phone"
	claims := map[string]any{
		"iss": keys.issuer, "sub": principal.Subject, "aud": "urn:dsh-mobile-ustc:device-registration",
		"iat": keys.now.Unix(), "jti": "approval-proof-unique-0001",
		"approval_key_jkt": approvalJKT, "proof_key_jkt": keys.proofJKT,
		"device_name_sha256": deviceNameDigestForTest(deviceName), "dpop_jti": principal.ProofJTI,
	}
	sign := func(claims map[string]any, signer *ecdsa.PrivateKey) string {
		return signCompact(t, map[string]any{"typ": deviceRegistrationProofType, "alg": "ES256"}, claims, signer)
	}
	validProof := sign(claims, approvalKey)
	if err := keys.verifier.VerifyDeviceRegistrationProof(validProof, approvalJSON, principal, deviceName, keys.proofJKT); err != nil {
		t.Fatalf("valid proof-of-possession rejected: %v", err)
	}

	for name, mutate := range map[string]func(map[string]any){
		"different request": func(claims map[string]any) { claims["dpop_jti"] = "another-dpop-proof-0002" },
		"different user":    func(claims map[string]any) { claims["sub"] = "other-user" },
		"different device name": func(claims map[string]any) {
			claims["device_name_sha256"] = deviceNameDigestForTest("other phone")
		},
		"different approval key": func(claims map[string]any) { claims["approval_key_jkt"] = keys.proofJKT },
		"unknown claim":          func(claims map[string]any) { claims["admin"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]any, len(claims))
			for key, value := range claims {
				candidate[key] = value
			}
			mutate(candidate)
			if err := keys.verifier.VerifyDeviceRegistrationProof(sign(candidate, approvalKey), approvalJSON, principal, deviceName, keys.proofJKT); err == nil {
				t.Fatal("mismatched approval proof was accepted")
			}
		})
	}
	if err := keys.verifier.VerifyDeviceRegistrationProof(sign(claims, keys.proof), approvalJSON, principal, deviceName, keys.proofJKT); err == nil {
		t.Fatal("proof signed by the DPoP key instead of approval key was accepted")
	}
}

func deviceNameDigestForTest(name string) string {
	digest := sha256.Sum256([]byte(name))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
