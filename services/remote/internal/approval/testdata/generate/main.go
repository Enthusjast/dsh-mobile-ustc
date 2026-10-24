// Generate public authorization interoperability fixtures. Private keys remain
// in this process and are never serialized, persisted or printed.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"time"

	"dsh-mobile-ustc/services/remote/internal/approval"
	"dsh-mobile-ustc/services/remote/internal/auth"
)

func main() {
	var lease approval.AuthorizationLease
	if json.NewDecoder(io.LimitReader(os.Stdin, 16<<10)).Decode(&lease) != nil { os.Exit(1) }
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { os.Exit(1) }
	public, err := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))})
	if err != nil { os.Exit(1) }
	jkt, err := auth.PublicP256JWKThumbprintJSON(public)
	if err != nil { os.Exit(1) }
	const keyID = "dsh-approval-authority/go-fixture"
	compact, err := approval.SignAuthorization(lease, keyID, key)
	if err != nil { os.Exit(1) }
	issued, err := time.Parse(time.RFC3339Nano, lease.IssuedAt)
	if err != nil { os.Exit(1) }
	if json.NewEncoder(os.Stdout).Encode(map[string]any{"compact": compact, "authority": map[string]any{
		"issuer": lease.Issuer, "key_id": keyID, "public_jwk": json.RawMessage(public), "key_jkt": jkt, "active": true,
		"valid_from": issued.Add(-time.Hour).Format("2006-01-02T15:04:05.000Z"), "valid_until": issued.Add(time.Hour).Format("2006-01-02T15:04:05.000Z"),
	}}) != nil { os.Exit(1) }
}
