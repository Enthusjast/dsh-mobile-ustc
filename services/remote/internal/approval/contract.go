package approval

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

const ContextDomain = "dsh-mobile-ustc/approval-context/v1"
const DecisionDomain = "dsh-mobile-ustc/approval-decision/v1"
const JWSType = "dsh-approval-decision+jws"
const utcFormat = "2006-01-02T15:04:05.000Z"
const maxSafeInteger = 9_007_199_254_740_991

var ErrContext = errors.New("approval: invalid request context")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var sha256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
var assuranceProfile = regexp.MustCompile(`^[a-z0-9][a-z0-9./_-]{0,127}$`)

type Identity struct {
	HostID         string `json:"host_id"`
	InstallationID string `json:"installation_id"`
	RuntimeID      string `json:"runtime_id"`
	RuntimeEpoch   string `json:"runtime_epoch"`
	SessionID      string `json:"session_id"`
	ApprovalID     string `json:"approval_id"`
	ExecutionID    string `json:"execution_id"`
}
type Workspace struct {
	WorkspaceID string `json:"workspace_id"`
	RootSHA256  string `json:"root_sha256"`
}
type Resource struct {
	Kind          string `json:"kind"`
	ResourceID    string `json:"resource_id"`
	VersionSHA256 string `json:"version_sha256"`
}
type Assurance struct {
	Profile           string `json:"profile"`
	MaxAuthAgeSeconds *int64 `json:"max_auth_age_seconds"`
}
type Context struct {
	Domain          string `json:"domain"`
	ProtocolVersion int    `json:"protocol_version"`
	Identity
	DSHSessionID      string          `json:"dsh_session_id"`
	CallID            string          `json:"call_id"`
	Tool              string          `json:"tool"`
	Arguments         json.RawMessage `json:"arguments"`
	Workspace         Workspace       `json:"workspace"`
	Resources         []Resource      `json:"resources"`
	Nonce             string          `json:"nonce"`
	PolicyVersion     int64           `json:"policy_version"`
	RequiredAssurance Assurance       `json:"required_assurance"`
	CreatedAt         string          `json:"created_at"`
	ExpiresAt         string          `json:"expires_at"`
}
type Decision struct {
	Domain          string `json:"domain"`
	ProtocolVersion int    `json:"protocol_version"`
	Identity
	BindingSHA256 string `json:"binding_sha256"`
	Decision      string `json:"decision"`
	UserID        string `json:"user_id"`
	DeviceID      string `json:"device_id"`
	KeyVersion    int64  `json:"key_version"`
	PolicyVersion int64  `json:"policy_version"`
	Nonce         string `json:"nonce"`
	IssuedAt      string `json:"issued_at"`
	ExpiresAt     string `json:"expires_at"`
}
type Binding struct {
	Context   Context
	Canonical []byte
	SHA256    string
}

func ContextBinding(raw []byte) (Binding, error) {
	encoded, err := canonical.Object(raw)
	if err != nil {
		return Binding{}, ErrContext
	}
	var context Context
	if decodeStrict(encoded, &context) != nil || !context.valid() {
		return Binding{}, ErrContext
	}
	digest := sha256.Sum256(encoded)
	return Binding{Context: context, Canonical: encoded, SHA256: hex.EncodeToString(digest[:])}, nil
}

func (identity Identity) valid() bool {
	for _, id := range []string{identity.HostID, identity.InstallationID, identity.RuntimeID, identity.RuntimeEpoch, identity.SessionID, identity.ApprovalID, identity.ExecutionID} {
		if !uuid.MatchString(id) {
			return false
		}
	}
	return true
}

func (context Context) valid() bool {
	if context.Domain != ContextDomain || context.ProtocolVersion != 1 || !context.Identity.valid() ||
		!text(context.DSHSessionID, 2048) || !text(context.CallID, 2048) || !text(context.Tool, 128) || len(context.Arguments) == 0 ||
		!uuid.MatchString(context.Workspace.WorkspaceID) || !sha256Pattern.MatchString(context.Workspace.RootSHA256) ||
		context.Resources == nil || len(context.Resources) > 256 || !validNonce(context.Nonce) || !version(context.PolicyVersion) ||
		!assuranceProfile.MatchString(context.RequiredAssurance.Profile) || context.RequiredAssurance.MaxAuthAgeSeconds == nil ||
		*context.RequiredAssurance.MaxAuthAgeSeconds < 0 || *context.RequiredAssurance.MaxAuthAgeSeconds > 900 {
		return false
	}
	created, createdOK := utc(context.CreatedAt)
	expires, expiresOK := utc(context.ExpiresAt)
	if !createdOK || !expiresOK || !expires.After(created) || expires.Sub(created) > 3*time.Minute {
		return false
	}
	resources := map[string]bool{}
	for _, resource := range context.Resources {
		key := resource.Kind + "\x00" + resource.ResourceID
		if (resource.Kind != "file" && resource.Kind != "repository" && resource.Kind != "artifact") || !text(resource.ResourceID, 2048) ||
			!sha256Pattern.MatchString(resource.VersionSHA256) || resources[key] {
			return false
		}
		resources[key] = true
	}
	return true
}

func (decision Decision) valid() bool {
	_, issued := utc(decision.IssuedAt)
	_, expires := utc(decision.ExpiresAt)
	return decision.Domain == DecisionDomain && decision.ProtocolVersion == 1 && decision.Identity.valid() && sha256Pattern.MatchString(decision.BindingSHA256) &&
		(decision.Decision == "allow_once" || decision.Decision == "reject") && uuid.MatchString(decision.UserID) && uuid.MatchString(decision.DeviceID) &&
		version(decision.KeyVersion) && version(decision.PolicyVersion) && validNonce(decision.Nonce) && issued && expires
}

func text(value string, max int) bool {
	if len(value) == 0 || len(value) > max {
		return false
	}
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return false
		}
	}
	return true
}
func version(value int64) bool { return value >= 1 && value <= maxSafeInteger }
func validNonce(value string) bool {
	bytes, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(bytes) == 32 && base64.RawURLEncoding.EncodeToString(bytes) == value
}
func utc(value string) (time.Time, bool) {
	parsed, err := time.Parse(utcFormat, value)
	return parsed, err == nil && parsed.Format(utcFormat) == value
}
func decodeStrict(raw []byte, target any) error {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	if !exactFieldNames(value, reflect.TypeOf(target)) {
		return ErrContext
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}

// encoding/json otherwise accepts field names case-insensitively. Approval
// schemas require exact names, including nested facts and embedded identities.
func exactFieldNames(value any, kind reflect.Type) bool {
	for kind.Kind() == reflect.Pointer {
		kind = kind.Elem()
	}
	if value == nil || kind == reflect.TypeOf(json.RawMessage{}) {
		return true
	}
	switch kind.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := map[string]reflect.Type{}
		var collect func(reflect.Type)
		collect = func(owner reflect.Type) {
			for owner.Kind() == reflect.Pointer {
				owner = owner.Elem()
			}
			for index := 0; index < owner.NumField(); index++ {
				field := owner.Field(index)
				name := strings.Split(field.Tag.Get("json"), ",")[0]
				if field.Anonymous && name == "" {
					collect(field.Type)
					continue
				}
				if name != "" && name != "-" {
					fields[name] = field.Type
				}
			}
		}
		collect(kind)
		for name, member := range object {
			field, ok := fields[name]
			if !ok || !exactFieldNames(member, field) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		array, ok := value.([]any)
		if !ok {
			return false
		}
		for _, item := range array {
			if !exactFieldNames(item, kind.Elem()) {
				return false
			}
		}
	}
	return true
}
