package approval

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"dsh-mobile-ustc/services/remote/internal/auth"
	"dsh-mobile-ustc/services/remote/internal/canonical"
	jose "github.com/go-jose/go-jose/v4"
)

const AuthorizationDomain = "dsh-mobile-ustc/approval-authorization/v1"
const AuthorizationAudience = "dsh-approval-host/v1"
const AuthorizationJWSType = "dsh-approval-authorization+jws"

var ErrAuthorization = errors.New("approval: invalid signed authorization")
var authorityKeyID = regexp.MustCompile(`^dsh-approval-authority/[A-Za-z0-9._-]{1,80}$`)

// AuthorizationLease attests a current, already accepted decision and device key.
// It grants only the exact binding on one host connection for at most 3 seconds.
type AuthorizationLease struct {
	Domain          string `json:"domain"`
	ProtocolVersion int    `json:"protocol_version"`
	Issuer          string `json:"issuer"`
	Audience        string `json:"audience"`
	Identity
	ConnectionID          string          `json:"connection_id"`
	LeaseID               string          `json:"lease_id"`
	Action                string          `json:"action"`
	Role                  string          `json:"role"`
	BindingSHA256         string          `json:"binding_sha256"`
	DecisionPayloadSHA256 string          `json:"decision_payload_sha256"`
	PolicyVersion         int64           `json:"policy_version"`
	UserID                string          `json:"user_id"`
	DeviceID              string          `json:"device_id"`
	KeyVersion            int64           `json:"key_version"`
	ApprovalKeyJKT        string          `json:"approval_key_jkt"`
	ApprovalPublicJWK     json.RawMessage `json:"approval_public_jwk"`
	GrantVersion          int64           `json:"grant_version"`
	AssuranceProfile      string          `json:"assurance_profile"`
	AuthenticatedAt       string          `json:"authenticated_at"`
	IssuedAt              string          `json:"issued_at"`
	ExpiresAt             string          `json:"expires_at"`
}

// TrustedAuthority is supplied by installation configuration, never by a phone,
// JWS header or the peer returning a lease. Key rotation replaces this trust set.
type TrustedAuthority struct {
	Issuer     string
	KeyID      string
	PublicJWK  []byte
	JKT        string
	Active     bool
	ValidFrom  time.Time
	ValidUntil time.Time
}

type VerifiedAuthorization struct {
	Lease    AuthorizationLease
	Key      RegisteredKey
	Decision VerifiedDecision
}

func (lease AuthorizationLease) valid() bool {
	issued, issuedOK := utc(lease.IssuedAt)
	expires, expiresOK := utc(lease.ExpiresAt)
	authenticated, authOK := utc(lease.AuthenticatedAt)
	if lease.Domain != AuthorizationDomain || lease.ProtocolVersion != 1 || lease.Audience != AuthorizationAudience || !validAuthorityIssuer(lease.Issuer) ||
		!lease.Identity.valid() || !uuid.MatchString(lease.ConnectionID) || !uuid.MatchString(lease.LeaseID) || lease.Action != "approval.decide" || lease.Role != "owner" ||
		!sha256Pattern.MatchString(lease.BindingSHA256) || !sha256Pattern.MatchString(lease.DecisionPayloadSHA256) || !version(lease.PolicyVersion) ||
		!uuid.MatchString(lease.UserID) || !uuid.MatchString(lease.DeviceID) || !version(lease.KeyVersion) || !version(lease.GrantVersion) ||
		!assuranceProfile.MatchString(lease.AssuranceProfile) || !issuedOK || !expiresOK || !authOK || authenticated.After(issued) ||
		!expires.After(issued) || expires.Sub(issued) > 3*time.Second {
		return false
	}
	// Only the four public EC members are signed into the lease. This prevents
	// embedded key URLs, private material or conflicting JWK metadata.
	jkt, err := barePublicP256(lease.ApprovalPublicJWK)
	return err == nil && jkt == lease.ApprovalKeyJKT
}

func barePublicP256(raw []byte) (string, error) {
	var key struct {
		Type  string `json:"kty"`
		Curve string `json:"crv"`
		X     string `json:"x"`
		Y     string `json:"y"`
	}
	if decodeStrict(raw, &key) != nil {
		return "", ErrAuthorization
	}
	for _, coordinate := range []string{key.X, key.Y} {
		decoded, err := base64.RawURLEncoding.Strict().DecodeString(coordinate)
		if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != coordinate {
			return "", ErrAuthorization
		}
	}
	return auth.PublicP256JWKThumbprintJSON(raw)
}

func validAuthorityIssuer(value string) bool {
	issuer, err := url.Parse(value)
	return err == nil && strings.HasPrefix(value, "https://") && issuer.Scheme == "https" && issuer.Host != "" && issuer.User == nil && issuer.Opaque == "" &&
		!strings.ContainsAny(value, "?# ") && strings.IndexFunc(value, unicode.IsControl) < 0 && len(value) <= 512
}

func SignAuthorization(lease AuthorizationLease, keyID string, private *ecdsa.PrivateKey) (string, error) {
	if !lease.valid() || !authorityKeyID.MatchString(keyID) || private == nil || private.Curve != elliptic.P256() || private.D == nil || private.D.Sign() <= 0 ||
		private.D.Cmp(elliptic.P256().Params().N) >= 0 || private.X == nil || private.Y == nil || !private.Curve.IsOnCurve(private.X, private.Y) {
		return "", ErrAuthorization
	}
	x, y := elliptic.P256().ScalarBaseMult(private.D.Bytes())
	if x.Cmp(private.X) != 0 || y.Cmp(private.Y) != 0 {
		return "", ErrAuthorization
	}
	raw, err := json.Marshal(lease)
	if err != nil {
		return "", ErrAuthorization
	}
	payload, err := canonical.Object(raw)
	if err != nil {
		return "", ErrAuthorization
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: private, KeyID: keyID}}, (&jose.SignerOptions{}).WithType(AuthorizationJWSType))
	if err != nil {
		return "", ErrAuthorization
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", ErrAuthorization
	}
	compact, err := signed.CompactSerialize()
	if err != nil {
		return "", ErrAuthorization
	}
	return compact, nil
}

// VerifyAuthorization verifies both authority and phone signatures. It does not
// consume the execution: the host's durable one-use guard must still do so.
func VerifyAuthorization(compact string, authority TrustedAuthority, expectedContext []byte, decisionJWS, connectionID string, now time.Time) (VerifiedAuthorization, error) {
	now = now.UTC().Truncate(time.Millisecond)
	if !authority.Active || !validAuthorityIssuer(authority.Issuer) || !authorityKeyID.MatchString(authority.KeyID) ||
		authority.ValidFrom.IsZero() || authority.ValidFrom.After(now) || !authority.ValidUntil.After(now) || !authority.ValidUntil.After(authority.ValidFrom) ||
		!uuid.MatchString(connectionID) || len(compact) == 0 || len(compact) > 16*1024 {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	decoded := make([][]byte, 3)
	for index, part := range parts {
		var err error
		decoded[index], err = base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil || len(decoded[index]) == 0 || base64.RawURLEncoding.EncodeToString(decoded[index]) != part {
			return VerifiedAuthorization{}, ErrAuthorization
		}
	}
	if len(decoded[2]) != 64 {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	headerRaw, err := canonical.Object(decoded[0])
	if err != nil || !bytes.Equal(headerRaw, decoded[0]) {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	var header struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}
	if decodeStrict(headerRaw, &header) != nil || header.Algorithm != "ES256" || header.KeyID != authority.KeyID || header.Type != AuthorizationJWSType {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	jkt, err := barePublicP256(authority.PublicJWK)
	if err != nil || jkt != authority.JKT {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	var key jose.JSONWebKey
	if json.Unmarshal(authority.PublicJWK, &key) != nil {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	signed, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil || len(signed.Signatures) != 1 {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	payload, err := signed.Verify(key.Key)
	if err != nil {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	encoded, err := canonical.Object(payload)
	if err != nil || !bytes.Equal(payload, encoded) {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	var lease AuthorizationLease
	if decodeStrict(encoded, &lease) != nil || !lease.valid() || lease.Issuer != authority.Issuer || lease.ConnectionID != connectionID {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	binding, err := ContextBinding(expectedContext)
	if err != nil || lease.Identity != binding.Context.Identity || lease.BindingSHA256 != binding.SHA256 || lease.PolicyVersion != binding.Context.PolicyVersion || lease.AssuranceProfile != binding.Context.RequiredAssurance.Profile {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	issued, _ := utc(lease.IssuedAt)
	expires, _ := utc(lease.ExpiresAt)
	authenticated, _ := utc(lease.AuthenticatedAt)
	requestExpires, _ := utc(binding.Context.ExpiresAt)
	if issued.After(now) || !expires.After(now) || issued.Before(authority.ValidFrom) || expires.After(authority.ValidUntil) || expires.After(requestExpires) ||
		authenticated.After(now) || expires.Sub(authenticated) > time.Duration(*binding.Context.RequiredAssurance.MaxAuthAgeSeconds)*time.Second {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	registered := RegisteredKey{UserID: lease.UserID, DeviceID: lease.DeviceID, KeyVersion: lease.KeyVersion, ApprovalKeyJKT: lease.ApprovalKeyJKT, PublicJWK: lease.ApprovalPublicJWK, Active: true}
	decision, err := VerifyDecision(decisionJWS, registered, expectedContext, now)
	if err != nil || decision.PayloadSHA256 != lease.DecisionPayloadSHA256 {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	decisionExpires, _ := utc(decision.Claims.ExpiresAt)
	if expires.After(decisionExpires) {
		return VerifiedAuthorization{}, ErrAuthorization
	}
	return VerifiedAuthorization{Lease: lease, Key: registered, Decision: decision}, nil
}

// AuthorizationSigner owns an immutable in-memory service key. Deployment key
// loading/wrapping and distribution of its public trust anchor are separate.
type AuthorizationSigner struct {
	private   *ecdsa.PrivateKey
	authority TrustedAuthority
}

func NewAuthorizationSigner(issuer, keyID string, private *ecdsa.PrivateKey, validFrom, validUntil time.Time) (*AuthorizationSigner, error) {
	if !validAuthorityIssuer(issuer) || !authorityKeyID.MatchString(keyID) || private == nil || private.Curve != elliptic.P256() ||
		private.D == nil || private.D.Sign() <= 0 || private.D.Cmp(elliptic.P256().Params().N) >= 0 || private.X == nil || private.Y == nil || !private.Curve.IsOnCurve(private.X, private.Y) ||
		validFrom.IsZero() || !validUntil.After(validFrom) || !validFrom.Equal(validFrom.Truncate(time.Millisecond)) || !validUntil.Equal(validUntil.Truncate(time.Millisecond)) {
		return nil, ErrAuthorization
	}
	expectedX, expectedY := elliptic.P256().ScalarBaseMult(private.D.Bytes())
	if expectedX.Cmp(private.X) != 0 || expectedY.Cmp(private.Y) != 0 {
		return nil, ErrAuthorization
	}
	// Serialize only into transient process memory to detach caller-owned big.Ints.
	raw, err := x509.MarshalECPrivateKey(private)
	if err != nil {
		return nil, ErrAuthorization
	}
	key, err := x509.ParseECPrivateKey(raw)
	clear(raw)
	if err != nil || key.X == nil || key.Y == nil {
		return nil, ErrAuthorization
	}
	x, y := elliptic.P256().ScalarBaseMult(key.D.Bytes())
	if x.Cmp(key.X) != 0 || y.Cmp(key.Y) != 0 {
		return nil, ErrAuthorization
	}
	public, err := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, 32))), "y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, 32)))})
	if err != nil {
		return nil, ErrAuthorization
	}
	jkt, err := barePublicP256(public)
	if err != nil {
		return nil, ErrAuthorization
	}
	return &AuthorizationSigner{private: key, authority: TrustedAuthority{Issuer: issuer, KeyID: keyID, PublicJWK: public, JKT: jkt, Active: true, ValidFrom: validFrom.UTC(), ValidUntil: validUntil.UTC()}}, nil
}

func (signer *AuthorizationSigner) Authority() TrustedAuthority {
	if signer == nil {
		return TrustedAuthority{}
	}
	authority := signer.authority
	authority.PublicJWK = bytes.Clone(authority.PublicJWK)
	return authority
}

func (signer *AuthorizationSigner) Sign(lease AuthorizationLease, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrAuthorization
	}
	issued, issuedOK := utc(lease.IssuedAt)
	expires, expiresOK := utc(lease.ExpiresAt)
	if !issuedOK || !expiresOK || lease.Issuer != signer.authority.Issuer || issued.After(now) || !expires.After(now) ||
		issued.Before(signer.authority.ValidFrom) || expires.After(signer.authority.ValidUntil) {
		return "", ErrAuthorization
	}
	return SignAuthorization(lease, signer.authority.KeyID, signer.private)
}
