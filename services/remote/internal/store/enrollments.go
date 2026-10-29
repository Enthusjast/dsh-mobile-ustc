package store

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

var ErrEnrollmentInvalid = errors.New("store: enrollment is invalid")
var ErrEnrollmentConflict = errors.New("store: enrollment request conflicts")
var ErrEnrollmentLimit = errors.New("store: enrollment limit reached")

var profileRefPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var keyThumbprintPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Legacy resources without enrollment rows were explicitly provisioned. Every
// API-created profile has a row and stays unavailable until both confirmations.
const runtimeEnrollmentApprovedSQL = `not exists (select 1 from enrollments binding where binding.runtime_id = r.id and binding.state <> 'approved')`
const installationHasApprovedRuntimeSQL = `exists (select 1 from runtimes r where r.installation_id = i.id and r.revoked_at is null and ` + runtimeEnrollmentApprovedSQL + `)`

type enrollmentQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type EnrollmentInput struct {
	Issuer                    string
	Subject                   string
	RequestID                 string
	OrganizationID            string
	HostID                    string
	Alias                     string
	ProfileRef                string
	DSHVersion                string
	ApplicationVersion        string
	PluginVersion             string
	ProtocolVersion           int
	InstallationPublicJWK     []byte
	InstallationKeyThumbprint string
	Code                      string
	WorkspaceRefs             []string
}

type EnrollmentWorkspace struct {
	Reference string `json:"reference"`
	ID        string `json:"workspace_id"`
}

type EnrollmentCreated struct {
	EnrollmentID   string                `json:"enrollment_id"`
	RequestID      string                `json:"request_id"`
	HostID         string                `json:"host_id"`
	InstallationID string                `json:"installation_id"`
	RuntimeID      string                `json:"runtime_id"`
	ProfileRef     string                `json:"profile_ref"`
	State          string                `json:"state"`
	ExpiresAt      time.Time             `json:"expires_at"`
	Workspaces     []EnrollmentWorkspace `json:"workspaces"`
}

type EnrollmentInfo struct {
	EnrollmentID       string                `json:"enrollment_id"`
	RequestID          string                `json:"request_id"`
	OrganizationID     string                `json:"organization_id"`
	OrganizationName   string                `json:"organization_name"`
	HostID             string                `json:"host_id"`
	HostAlias          string                `json:"host_alias"`
	InstallationID     string                `json:"installation_id"`
	InstallationKeyJKT string                `json:"installation_key_jkt"`
	RuntimeID          string                `json:"runtime_id"`
	ProfileRef         string                `json:"profile_ref"`
	DSHVersion         string                `json:"dsh_version,omitempty"`
	ApplicationVersion string                `json:"application_version,omitempty"`
	PluginVersion      string                `json:"plugin_version,omitempty"`
	ProtocolVersion    int                   `json:"protocol_version"`
	State              string                `json:"state"`
	ExpiresAt          time.Time             `json:"expires_at"`
	HostConfirmed      bool                  `json:"host_confirmed"`
	UserConfirmed      bool                  `json:"user_confirmed"`
	UserConfirmedByMe  bool                  `json:"user_confirmed_by_me"`
	Workspaces         []EnrollmentWorkspace `json:"workspaces"`
	// These values are never serialized in phone/status responses. They are
	// disclosed only by the installation-owner, key-bound host review route.
	HostReviewOwner bool                  `json:"-"`
	HostReviewUser  *EnrollmentReviewUser `json:"-"`
}

type EnrollmentReviewUser struct {
	UserID   string `json:"user_id"`
	Issuer   string `json:"issuer"`
	Subject  string `json:"subject"`
	Eligible bool   `json:"eligible"`
}

type EnrollmentHostReview struct {
	Enrollment    EnrollmentInfo        `json:"enrollment"`
	ConfirmedUser *EnrollmentReviewUser `json:"confirmed_user"`
}

type EnrollmentConfirmation struct {
	EnrollmentID  string    `json:"enrollment_id"`
	HostID        string    `json:"host_id"`
	RuntimeID     string    `json:"runtime_id"`
	State         string    `json:"state"`
	ExpiresAt     time.Time `json:"expires_at"`
	HostConfirmed bool      `json:"host_confirmed"`
	UserConfirmed bool      `json:"user_confirmed"`
}

type enrollmentRow struct {
	ID                            string
	HostID                        string
	InstallationID                string
	RuntimeID                     string
	RequestedBy                   string
	OrgID                         string
	State                         string
	CodeHash                      []byte
	ExpiresAt                     time.Time
	Expired                       bool
	UserConfirmedBy               sql.NullString
	UserConfirmedAt               sql.NullTime
	UserConfirmedDeviceID         sql.NullString
	UserConfirmedDeviceKeyVersion sql.NullInt64
	HostConfirmedAt               sql.NullTime
	HostState                     string
	InstallationRevoked           sql.NullTime
	RuntimeRevoked                sql.NullTime
	InstallationOwnerID           string
	InstallationKeyJKT            string
}

func NormalizeEnrollmentInput(input EnrollmentInput) (EnrollmentInput, []byte, []byte, error) {
	input.Alias = strings.TrimSpace(input.Alias)
	input.ProfileRef = strings.TrimSpace(input.ProfileRef)
	input.DSHVersion = strings.TrimSpace(input.DSHVersion)
	input.ApplicationVersion = strings.TrimSpace(input.ApplicationVersion)
	input.PluginVersion = strings.TrimSpace(input.PluginVersion)
	if !grantUUIDPattern.MatchString(input.RequestID) || !grantUUIDPattern.MatchString(input.OrganizationID) ||
		input.HostID != "" && !grantUUIDPattern.MatchString(input.HostID) ||
		input.Issuer == "" || input.Subject == "" || input.Alias == "" || utf8.RuneCountInString(input.Alias) > 160 ||
		strings.IndexFunc(input.Alias, unicode.IsControl) >= 0 || !profileRefPattern.MatchString(input.ProfileRef) ||
		input.ProfileRef == "." || input.ProfileRef == ".." || input.ProtocolVersion < 1 || input.ProtocolVersion > 32 ||
		len(input.InstallationPublicJWK) == 0 || len(input.InstallationPublicJWK) > 8<<10 ||
		!keyThumbprintPattern.MatchString(input.InstallationKeyThumbprint) {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	for _, version := range []string{input.DSHVersion, input.ApplicationVersion, input.PluginVersion} {
		if len(version) > 128 || strings.IndexFunc(version, unicode.IsControl) >= 0 {
			return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
		}
	}
	var publicJWK map[string]any
	if json.Unmarshal(input.InstallationPublicJWK, &publicJWK) != nil || publicJWK == nil {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	thumbprint, err := auth.PublicP256JWKThumbprintJSON(input.InstallationPublicJWK)
	if err != nil || thumbprint != input.InstallationKeyThumbprint {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	if len(input.WorkspaceRefs) > 64 {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	refs, err := normalizeStrings(input.WorkspaceRefs, false)
	if err != nil {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	for _, ref := range refs {
		if !profileRefPattern.MatchString(ref) || ref == "." || ref == ".." {
			return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
		}
	}
	input.WorkspaceRefs = refs
	codeBytes, err := base64.RawURLEncoding.Strict().DecodeString(input.Code)
	if err != nil || len(codeBytes) != 32 || base64.RawURLEncoding.EncodeToString(codeBytes) != input.Code {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	for index := range codeBytes {
		codeBytes[index] = 0
	}
	codeHash := sha256.Sum256([]byte(input.Code))
	fingerprint, err := json.Marshal(struct {
		RequestID       string   `json:"request_id"`
		OrganizationID  string   `json:"organization_id"`
		HostID          string   `json:"host_id,omitempty"`
		Alias           string   `json:"alias"`
		ProfileRef      string   `json:"profile_ref"`
		DSHVersion      string   `json:"dsh_version"`
		Application     string   `json:"application_version"`
		PluginVersion   string   `json:"plugin_version"`
		ProtocolVersion int      `json:"protocol_version"`
		KeyThumbprint   string   `json:"installation_key_thumbprint"`
		CodeHash        string   `json:"code_hash"`
		WorkspaceRefs   []string `json:"workspace_refs"`
	}{input.RequestID, input.OrganizationID, input.HostID, input.Alias, input.ProfileRef, input.DSHVersion,
		input.ApplicationVersion, input.PluginVersion, input.ProtocolVersion, input.InstallationKeyThumbprint,
		base64.RawURLEncoding.EncodeToString(codeHash[:]), input.WorkspaceRefs})
	if err != nil {
		return EnrollmentInput{}, nil, nil, ErrEnrollmentInvalid
	}
	requestHash := sha256.Sum256(fingerprint)
	return input, codeHash[:], requestHash[:], nil
}

func (postgres *Postgres) CreateEnrollment(ctx context.Context, input EnrollmentInput) (EnrollmentCreated, error) {
	input, codeHash, requestHash, err := NormalizeEnrollmentInput(input)
	if err != nil {
		return EnrollmentCreated{}, err
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	userID, err := postgres.userID(ctx, transaction, input.Issuer, input.Subject)
	if err != nil {
		return EnrollmentCreated{}, err
	}
	var membershipRole string
	err = transaction.QueryRowContext(ctx, `
		select role from org_memberships where org_id = $1 and user_id = $2 for share`, input.OrganizationID, userID).Scan(&membershipRole)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentCreated{}, ErrAccessDenied
	}
	if err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	var existingID string
	var existingRequestHash, existingCodeHash []byte
	err = transaction.QueryRowContext(ctx, `
		select id::text, request_sha256, code_hash from enrollments
		where requested_by = $1 and request_id = $2 for update`, userID, input.RequestID).
		Scan(&existingID, &existingRequestHash, &existingCodeHash)
	if err == nil {
		if subtle.ConstantTimeCompare(existingRequestHash, requestHash) != 1 || subtle.ConstantTimeCompare(existingCodeHash, codeHash) != 1 {
			return EnrollmentCreated{}, ErrEnrollmentConflict
		}
		result, err := enrollmentCreated(ctx, transaction, existingID)
		if err != nil {
			return EnrollmentCreated{}, err
		}
		if err := transaction.Commit(); err != nil {
			return EnrollmentCreated{}, ErrDatabaseUnavailable
		}
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	var userPending, orgPending int
	if err := transaction.QueryRowContext(ctx, `
		select count(*) from enrollments
		where requested_by = $1 and state in ('pending','user_confirmed') and expires_at > clock_timestamp()`, userID).Scan(&userPending); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	if err := transaction.QueryRowContext(ctx, `
		select count(*) from enrollments e
		join hosts h on h.id = e.host_id
		where h.org_id = $1 and e.state in ('pending','user_confirmed') and e.expires_at > clock_timestamp()`, input.OrganizationID).Scan(&orgPending); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	if userPending >= 10 || orgPending >= 100 {
		return EnrollmentCreated{}, ErrEnrollmentLimit
	}
	var hostID, installationID, runtimeID string
	var installationOwnerID, hostOrgID, hostAlias, hostState string
	var installationRevoked sql.NullTime
	err = transaction.QueryRowContext(ctx, `
		select i.id::text, i.host_id::text, i.owner_user_id::text, h.org_id::text, h.alias, h.state, i.revoked_at
		from installations i join hosts h on h.id = i.host_id
		where i.public_key_thumbprint = $1
		for update of i, h`, input.InstallationKeyThumbprint).
		Scan(&installationID, &hostID, &installationOwnerID, &hostOrgID, &hostAlias, &hostState, &installationRevoked)
	if err == nil {
		if installationRevoked.Valid || hostState == "revoked" || installationOwnerID != userID ||
			hostOrgID != input.OrganizationID || hostAlias != input.Alias || input.HostID != "" && input.HostID != hostID {
			return EnrollmentCreated{}, ErrEnrollmentConflict
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		if input.HostID == "" {
			if err := transaction.QueryRowContext(ctx, `
				insert into hosts (org_id, alias, state) values ($1, $2, 'pending') returning id::text`,
				input.OrganizationID, input.Alias).Scan(&hostID); err != nil {
				return EnrollmentCreated{}, ErrDatabaseUnavailable
			}
		} else {
			err := transaction.QueryRowContext(ctx, `
				select org_id::text, alias, state from hosts where id = $1 for update`, input.HostID).
				Scan(&hostOrgID, &hostAlias, &hostState)
			if errors.Is(err, sql.ErrNoRows) || hostOrgID != input.OrganizationID || hostAlias != input.Alias || hostState != "active" {
				return EnrollmentCreated{}, ErrAccessDenied
			}
			if err != nil {
				return EnrollmentCreated{}, ErrDatabaseUnavailable
			}
			if membershipRole != "admin" {
				var ownsInstallation bool
				if err := transaction.QueryRowContext(ctx, `
					select exists(select 1 from installations where host_id = $1 and owner_user_id = $2 and revoked_at is null)`,
					input.HostID, userID).Scan(&ownsInstallation); err != nil {
					return EnrollmentCreated{}, ErrDatabaseUnavailable
				}
				if !ownsInstallation {
					return EnrollmentCreated{}, ErrAccessDenied
				}
			}
			hostID = input.HostID
		}
		if err := transaction.QueryRowContext(ctx, `
			insert into installations (host_id, owner_user_id, public_jwk, public_key_thumbprint)
			values ($1, $2, $3::jsonb, $4) returning id::text`,
			hostID, userID, string(input.InstallationPublicJWK), input.InstallationKeyThumbprint).Scan(&installationID); err != nil {
			return EnrollmentCreated{}, ErrDatabaseUnavailable
		}
	} else {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	var runtimeAlreadyExists bool
	if err := transaction.QueryRowContext(ctx, `
		select exists(select 1 from runtimes where installation_id = $1 and profile_ref = $2)`,
		installationID, input.ProfileRef).Scan(&runtimeAlreadyExists); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	if runtimeAlreadyExists {
		return EnrollmentCreated{}, ErrEnrollmentConflict
	}
	if err := transaction.QueryRowContext(ctx, `
		insert into runtimes (installation_id, profile_ref, dsh_version, application_version, plugin_version, protocol_version)
		values ($1, $2, $3, $4, $5, $6) returning id::text`,
		installationID, input.ProfileRef, input.DSHVersion, input.ApplicationVersion, input.PluginVersion, input.ProtocolVersion).Scan(&runtimeID); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	for _, workspaceRef := range input.WorkspaceRefs {
		if _, err := transaction.ExecContext(ctx, `insert into workspaces (runtime_id, workspace_ref) values ($1, $2)`, runtimeID, workspaceRef); err != nil {
			return EnrollmentCreated{}, ErrDatabaseUnavailable
		}
	}
	var enrollmentID string
	var expiresAt time.Time
	err = transaction.QueryRowContext(ctx, `
		insert into enrollments (request_id, request_sha256, host_id, installation_id, runtime_id,
		                         requested_by, code_hash, expires_at)
		values ($1, $2, $3, $4, $5, $6, $7, clock_timestamp() + interval '5 minutes')
		returning id::text, expires_at`, input.RequestID, requestHash, hostID, installationID, runtimeID, userID, codeHash).
		Scan(&enrollmentID, &expiresAt)
	if err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	metadata, _ := json.Marshal(map[string]string{"enrollment_id": enrollmentID, "request_id": input.RequestID, "host_id": hostID, "installation_id": installationID, "runtime_id": runtimeID})
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, runtime_id, action, result, metadata)
		values ($1, 'user', $2, $3, 'enrollment.create', 'success', $4::jsonb)`, input.OrganizationID, userID, runtimeID, string(metadata)); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into control_outbox (org_id, topic, payload) values ($1, 'enrollment.created', $2::jsonb)`, input.OrganizationID, string(metadata)); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	workspaces, err := enrollmentWorkspaces(ctx, transaction, runtimeID)
	if err != nil {
		return EnrollmentCreated{}, err
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	return EnrollmentCreated{EnrollmentID: enrollmentID, RequestID: input.RequestID, HostID: hostID,
		InstallationID: installationID, RuntimeID: runtimeID, ProfileRef: input.ProfileRef,
		State: "pending", ExpiresAt: expiresAt, Workspaces: workspaces}, nil
}

func enrollmentCreated(ctx context.Context, query enrollmentQuery, enrollmentID string) (EnrollmentCreated, error) {
	var result EnrollmentCreated
	err := query.QueryRowContext(ctx, `
		select e.id::text, e.request_id::text, e.host_id::text, e.installation_id::text,
		       e.runtime_id::text, r.profile_ref,
		       case when e.state in ('pending','user_confirmed') and e.expires_at <= clock_timestamp() then 'expired' else e.state end,
	       e.expires_at
		from enrollments e join runtimes r on r.id = e.runtime_id
		where e.id = $1`, enrollmentID).
		Scan(&result.EnrollmentID, &result.RequestID, &result.HostID, &result.InstallationID,
			&result.RuntimeID, &result.ProfileRef, &result.State, &result.ExpiresAt)
	if err != nil {
		return EnrollmentCreated{}, ErrDatabaseUnavailable
	}
	result.Workspaces, err = enrollmentWorkspaces(ctx, query, result.RuntimeID)
	if err != nil {
		return EnrollmentCreated{}, err
	}
	return result, nil
}

func (postgres *Postgres) GetEnrollment(ctx context.Context, identity UserIdentity, enrollmentID string) (EnrollmentInfo, error) {
	return postgres.enrollmentInfo(ctx, identity, enrollmentID, nil)
}

// Preview requires possession of the code before disclosing another user's
// pending installation. The code stays in the request body and is never returned.
func (postgres *Postgres) PreviewEnrollment(ctx context.Context, identity UserIdentity, enrollmentID, code string) (EnrollmentInfo, error) {
	digest, err := enrollmentCodeHash(code)
	if err != nil {
		return EnrollmentInfo{}, ErrEnrollmentInvalid
	}
	return postgres.enrollmentInfo(ctx, identity, enrollmentID, digest)
}

func (postgres *Postgres) enrollmentInfo(ctx context.Context, identity UserIdentity, enrollmentID string, codeHash []byte) (EnrollmentInfo, error) {
	if !grantUUIDPattern.MatchString(enrollmentID) {
		return EnrollmentInfo{}, ErrEnrollmentInvalid
	}
	actorID, err := postgres.ActiveUser(ctx, identity)
	if err != nil {
		return EnrollmentInfo{}, err
	}
	var info EnrollmentInfo
	var userConfirmed sql.NullString
	var hostConfirmed sql.NullTime
	var expectedCodeHash []byte
	var codeExpired bool
	var installationOwner string
	var confirmedIssuer, confirmedSubject sql.NullString
	var confirmedEligible bool
	var confirmedDeviceID sql.NullString
	var confirmedDeviceKeyVersion sql.NullInt64
	err = postgres.DB.QueryRowContext(ctx, `
		select e.id::text, e.request_id::text, o.id::text, o.name, h.id::text, h.alias,
		       i.id::text, i.public_key_thumbprint, r.id::text, r.profile_ref, coalesce(r.dsh_version,''),
		       coalesce(r.application_version,''), coalesce(r.plugin_version,''), r.protocol_version,
		       case when e.state in ('pending','user_confirmed') and e.expires_at <= clock_timestamp() then 'expired' else e.state end,
		       e.expires_at, e.user_confirmed_by::text, e.host_confirmed_at, e.code_hash, e.expires_at <= clock_timestamp(),
		       i.owner_user_id::text, e.user_confirmed_device_id::text, e.user_confirmed_device_key_version,
		       case when i.owner_user_id = $2 then confirmed.issuer end,
		       case when i.owner_user_id = $2 then confirmed.subject end,
		       coalesce(i.owner_user_id = $2 and h.state <> 'revoked' and i.revoked_at is null and r.revoked_at is null and confirmed.status = 'active'
		         and exists(select 1 from org_memberships cm where cm.org_id = h.org_id and cm.user_id = confirmed.id)
		         and exists(select 1 from devices d where d.id = e.user_confirmed_device_id and d.user_id = confirmed.id
		                    and d.key_version = e.user_confirmed_device_key_version and d.revoked_at is null), false)
		from enrollments e
		join hosts h on h.id = e.host_id
		join orgs o on o.id = h.org_id
		join installations i on i.id = e.installation_id and i.host_id = h.id
		join runtimes r on r.id = e.runtime_id and r.installation_id = i.id
		join org_memberships m on m.org_id = h.org_id and m.user_id = $2
		left join users confirmed on confirmed.id = e.user_confirmed_by
		where e.id = $1 and (e.requested_by = $2 or e.user_confirmed_by = $2 or $3)`, enrollmentID, actorID, codeHash != nil).
		Scan(&info.EnrollmentID, &info.RequestID, &info.OrganizationID, &info.OrganizationName, &info.HostID, &info.HostAlias,
			&info.InstallationID, &info.InstallationKeyJKT, &info.RuntimeID, &info.ProfileRef, &info.DSHVersion, &info.ApplicationVersion,
			&info.PluginVersion, &info.ProtocolVersion, &info.State, &info.ExpiresAt, &userConfirmed, &hostConfirmed, &expectedCodeHash, &codeExpired,
			&installationOwner, &confirmedDeviceID, &confirmedDeviceKeyVersion, &confirmedIssuer, &confirmedSubject, &confirmedEligible)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentInfo{}, ErrAccessDenied
	}
	if err != nil {
		return EnrollmentInfo{}, ErrDatabaseUnavailable
	}
	if codeHash != nil && (codeExpired || subtle.ConstantTimeCompare(expectedCodeHash, codeHash) != 1) {
		return EnrollmentInfo{}, ErrEnrollmentInvalid
	}
	info.UserConfirmed = userConfirmed.Valid
	info.UserConfirmedByMe = userConfirmed.Valid && userConfirmed.String == actorID
	// A legacy host-first timestamp did not review a phone identity.
	info.HostConfirmed = hostConfirmed.Valid && userConfirmed.Valid && (info.State == "approved" || confirmedDeviceID.Valid && confirmedDeviceKeyVersion.Valid)
	info.HostReviewOwner = installationOwner == actorID
	if userConfirmed.Valid && info.HostReviewOwner {
		if !confirmedIssuer.Valid || !confirmedSubject.Valid {
			return EnrollmentInfo{}, ErrDatabaseUnavailable
		}
		info.HostReviewUser = &EnrollmentReviewUser{UserID: userConfirmed.String, Issuer: confirmedIssuer.String, Subject: confirmedSubject.String, Eligible: confirmedEligible}
	}
	info.Workspaces, err = enrollmentWorkspaces(ctx, postgres.DB, info.RuntimeID)
	if err != nil {
		return EnrollmentInfo{}, err
	}
	return info, nil
}

func (postgres *Postgres) ConfirmEnrollmentUser(ctx context.Context, identity UserIdentity, deviceID, proofKeyThumbprint, enrollmentID, code string) (EnrollmentConfirmation, error) {
	return postgres.confirmEnrollment(ctx, identity, deviceID, proofKeyThumbprint, enrollmentID, code, false, "", "")
}

func (postgres *Postgres) ConfirmEnrollmentHost(ctx context.Context, identity UserIdentity, installationKeyThumbprint, enrollmentID, code, confirmedUserID string) (EnrollmentConfirmation, error) {
	if !grantUUIDPattern.MatchString(confirmedUserID) {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	return postgres.confirmEnrollment(ctx, identity, "", "", enrollmentID, code, true, installationKeyThumbprint, confirmedUserID)
}

func (postgres *Postgres) confirmEnrollment(ctx context.Context, identity UserIdentity, deviceID, proofKeyThumbprint, enrollmentID, code string, hostConfirmation bool, installationKeyThumbprint, confirmedUserID string) (EnrollmentConfirmation, error) {
	if !grantUUIDPattern.MatchString(enrollmentID) {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	codeHash, err := enrollmentCodeHash(code)
	if err != nil {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	transaction, err := postgres.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	defer transaction.Rollback()
	actorID, err := postgres.userID(ctx, transaction, identity.Issuer, identity.Subject)
	if err != nil {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	row, err := loadEnrollmentForUpdate(ctx, transaction, enrollmentID)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	if err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	if subtle.ConstantTimeCompare(row.CodeHash, codeHash) != 1 {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	if row.HostState == "revoked" || row.InstallationRevoked.Valid || row.RuntimeRevoked.Valid {
		return EnrollmentConfirmation{}, ErrAccessDenied
	}
	var activeDeviceVersion int64
	if hostConfirmation {
		if actorID != row.InstallationOwnerID || installationKeyThumbprint != row.InstallationKeyJKT {
			return EnrollmentConfirmation{}, ErrAccessDenied
		}
	} else {
		var activeDevice string
		err := transaction.QueryRowContext(ctx, `
			select id::text,key_version from devices where id = $1 and user_id = $2 and proof_key_thumbprint = $3 and revoked_at is null for share`, deviceID, actorID, proofKeyThumbprint).Scan(&activeDevice, &activeDeviceVersion)
		if errors.Is(err, sql.ErrNoRows) {
			return EnrollmentConfirmation{}, ErrDeviceNotFound
		}
		if err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
	}
	var memberRole string
	err = transaction.QueryRowContext(ctx, `
		select role from org_memberships where org_id = $1 and user_id = $2 for share`, row.OrgID, actorID).Scan(&memberRole)
	if errors.Is(err, sql.ErrNoRows) {
		return EnrollmentConfirmation{}, ErrAccessDenied
	}
	if err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	if !hostConfirmation && row.UserConfirmedBy.Valid && row.UserConfirmedBy.String != actorID {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	if hostConfirmation && row.UserConfirmedBy.Valid && row.UserConfirmedBy.String != confirmedUserID {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	if row.State == "approved" {
		if hostConfirmation && !row.UserConfirmedBy.Valid {
			return EnrollmentConfirmation{}, ErrEnrollmentInvalid
		}
		if err := transaction.Commit(); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		return enrollmentConfirmation(row), nil
	}
	if row.State == "denied" || row.State == "cancelled" || row.State == "expired" {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	if row.Expired {
		if _, err := transaction.ExecContext(ctx, `update enrollments set state = 'expired' where id = $1`, row.ID); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `update runtimes set revoked_at = clock_timestamp() where id = $1 and revoked_at is null`, row.RuntimeID); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `update installations i set revoked_at = clock_timestamp()
			where i.id = $1 and i.revoked_at is null and not exists
			(select 1 from runtimes r where r.installation_id = i.id and r.revoked_at is null)`, row.InstallationID); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `update hosts h set state = 'revoked'
			where h.id = $1 and h.state = 'pending' and not exists
			(select 1 from installations i where i.host_id = h.id and i.revoked_at is null)`, row.HostID); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		actorType, actorIDForAudit, auditDeviceID := "device", deviceID, deviceID
		if hostConfirmation {
			actorType, actorIDForAudit, auditDeviceID = "installation", row.InstallationID, ""
		}
		var auditDeviceValue any
		if auditDeviceID != "" {
			auditDeviceValue = auditDeviceID
		}
		metadata, _ := json.Marshal(map[string]string{"enrollment_id": row.ID, "host_id": row.HostID, "installation_id": row.InstallationID, "runtime_id": row.RuntimeID, "state": "expired"})
		if _, err := transaction.ExecContext(ctx, `
			insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, action, result, metadata)
			values ($1, $2, $3, $4, $5, 'enrollment.expire', 'expired', $6::jsonb)`,
			row.OrgID, actorType, actorIDForAudit, auditDeviceValue, row.RuntimeID, string(metadata)); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		if _, err := transaction.ExecContext(ctx, `
			insert into control_outbox (org_id, topic, payload) values ($1, 'enrollment.expired', $2::jsonb)`, row.OrgID, string(metadata)); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		if err := transaction.Commit(); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	// A host decision must refer to an already confirmed phone identity. This
	// prevents a host-first decision from preauthorizing an unknown future user.
	if hostConfirmation && !row.UserConfirmedBy.Valid {
		return EnrollmentConfirmation{}, ErrEnrollmentInvalid
	}
	if hostConfirmation {
		if !row.UserConfirmedDeviceID.Valid || !row.UserConfirmedDeviceKeyVersion.Valid {
			return EnrollmentConfirmation{}, ErrEnrollmentInvalid
		}
		var activeDevice string
		err := transaction.QueryRowContext(ctx, `
			select id::text from devices where id=$1 and user_id=$2 and key_version=$3 and revoked_at is null for share`,
			row.UserConfirmedDeviceID.String, row.UserConfirmedBy.String, row.UserConfirmedDeviceKeyVersion.Int64).Scan(&activeDevice)
		if errors.Is(err, sql.ErrNoRows) {
			return EnrollmentConfirmation{}, ErrAccessDenied
		}
		if err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
	}
	changed := false
	if hostConfirmation && !row.HostConfirmedAt.Valid {
		row.HostConfirmedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		changed = true
	}
	if !hostConfirmation && !row.UserConfirmedBy.Valid {
		// Older versions allowed a host-first decision. Do not carry that
		// unreviewed decision into the first phone confirmation.
		row.HostConfirmedAt = sql.NullTime{}
		row.UserConfirmedBy = sql.NullString{String: actorID, Valid: true}
		row.UserConfirmedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		row.UserConfirmedDeviceID = sql.NullString{String: deviceID, Valid: true}
		row.UserConfirmedDeviceKeyVersion = sql.NullInt64{Int64: activeDeviceVersion, Valid: true}
		changed = true
	} else if !hostConfirmation && (!row.UserConfirmedDeviceID.Valid || row.UserConfirmedDeviceID.String != deviceID ||
		!row.UserConfirmedDeviceKeyVersion.Valid || row.UserConfirmedDeviceKeyVersion.Int64 != activeDeviceVersion) {
		// Reconfirmation with a different key or a legacy unbound record must
		// not carry forward an earlier host decision.
		row.HostConfirmedAt = sql.NullTime{}
		row.UserConfirmedAt = sql.NullTime{Time: time.Now().UTC(), Valid: true}
		row.UserConfirmedDeviceID = sql.NullString{String: deviceID, Valid: true}
		row.UserConfirmedDeviceKeyVersion = sql.NullInt64{Int64: activeDeviceVersion, Valid: true}
		changed = true
	}
	if !changed {
		if err := transaction.Commit(); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		return enrollmentConfirmation(row), nil
	}
	state := "pending"
	if row.UserConfirmedBy.Valid {
		state = "user_confirmed"
	}
	approved := row.UserConfirmedBy.Valid && row.HostConfirmedAt.Valid
	if approved {
		state = "approved"
	}
	if _, err := transaction.ExecContext(ctx, `
		update enrollments set state = $2, user_confirmed_by = $3, user_confirmed_at = $4,
		                      host_confirmed_at = $5, decided_by = $6, decided_at = $7,
		                      user_confirmed_device_id = $8, user_confirmed_device_key_version = $9
		where id = $1`, row.ID, state, nullStringValue(row.UserConfirmedBy), nullTimeValue(row.UserConfirmedAt),
		nullTimeValue(row.HostConfirmedAt), nullableUserID(approved, actorID), nullableTime(approved, time.Now().UTC()),
		nullStringValue(row.UserConfirmedDeviceID), row.UserConfirmedDeviceKeyVersion); err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	actorType, actorIDForAudit, auditDeviceID := "device", deviceID, deviceID
	if hostConfirmation {
		actorType, actorIDForAudit, auditDeviceID = "installation", row.InstallationID, ""
	}
	action := "enrollment.user_confirm"
	if hostConfirmation {
		action = "enrollment.host_confirm"
	}
	metadata, _ := json.Marshal(map[string]any{"enrollment_id": row.ID, "host_id": row.HostID, "installation_id": row.InstallationID, "runtime_id": row.RuntimeID, "state": state})
	if hostConfirmation {
		metadata, _ = json.Marshal(map[string]any{"enrollment_id": row.ID, "host_id": row.HostID, "installation_id": row.InstallationID, "runtime_id": row.RuntimeID, "state": state, "confirmed_user_id": confirmedUserID})
	}
	var auditDeviceValue any
	if auditDeviceID != "" {
		auditDeviceValue = auditDeviceID
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into audit_log (org_id, actor_type, actor_id, device_id, runtime_id, action, result, metadata)
		values ($1, $2, $3, $4, $5, $6, 'success', $7::jsonb)`,
		row.OrgID, actorType, actorIDForAudit, auditDeviceValue, row.RuntimeID, action, string(metadata)); err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	if _, err := transaction.ExecContext(ctx, `
		insert into control_outbox (org_id, topic, payload) values ($1, 'enrollment.state_changed', $2::jsonb)`, row.OrgID, string(metadata)); err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	if approved {
		if _, err := activeOrganizationUser(ctx, transaction, row.OrgID, row.InstallationOwnerID); err != nil {
			return EnrollmentConfirmation{}, ErrAccessDenied
		}
		if _, err := activeOrganizationUser(ctx, transaction, row.OrgID, row.UserConfirmedBy.String); err != nil {
			return EnrollmentConfirmation{}, ErrAccessDenied
		}
		if _, err := transaction.ExecContext(ctx, `update hosts set state = 'active' where id = $1 and state = 'pending'`, row.HostID); err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		workspaces, err := enrollmentWorkspaces(ctx, transaction, row.RuntimeID)
		if err != nil {
			return EnrollmentConfirmation{}, err
		}
		workspaceIDs := make([]string, 0, len(workspaces))
		for _, workspace := range workspaces {
			workspaceIDs = append(workspaceIDs, workspace.ID)
		}
		actions := make([]string, 0, len(roleActions["owner"]))
		for action := range roleActions["owner"] {
			actions = append(actions, action)
		}
		sort.Strings(actions)
		ownerGrant, err := NormalizeRuntimeGrantInput(RuntimeGrantInput{Role: "owner", Scope: GrantScope{
			Actions: actions, Workspaces: workspaceIDs, Sessions: []string{},
		}}, time.Now())
		if err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		scopeJSON, err := json.Marshal(ownerGrant.Scope)
		if err != nil {
			return EnrollmentConfirmation{}, ErrDatabaseUnavailable
		}
		owners := []string{row.InstallationOwnerID}
		if row.UserConfirmedBy.String != row.InstallationOwnerID {
			owners = append(owners, row.UserConfirmedBy.String)
		}
		for _, ownerID := range owners {
			if _, err := transaction.ExecContext(ctx, `
				insert into runtime_grants (runtime_id, user_id, role, scope, grant_version, granted_by)
				values ($1, $2, 'owner', $3::jsonb, 1, $4)`, row.RuntimeID, ownerID, string(scopeJSON), actorID); err != nil {
				return EnrollmentConfirmation{}, ErrDatabaseUnavailable
			}
			if err := writeGrantChange(ctx, transaction, actorID, auditDeviceID, row.OrgID, row.RuntimeID,
				ownerID, "owner", 1, nil, "runtime_grant.updated", "runtime_grant.update", scopeJSON); err != nil {
				return EnrollmentConfirmation{}, ErrDatabaseUnavailable
			}
		}
	}
	if err := transaction.Commit(); err != nil {
		return EnrollmentConfirmation{}, ErrDatabaseUnavailable
	}
	row.State = state
	return enrollmentConfirmation(row), nil
}

func loadEnrollmentForUpdate(ctx context.Context, transaction *sql.Tx, enrollmentID string) (enrollmentRow, error) {
	var row enrollmentRow
	err := transaction.QueryRowContext(ctx, `
		select e.id::text, e.host_id::text, e.installation_id::text, e.runtime_id::text,
		       e.requested_by::text, h.org_id::text, e.state, e.code_hash, e.expires_at <= clock_timestamp(),
	       e.expires_at, e.user_confirmed_by::text, e.user_confirmed_at, e.user_confirmed_device_id::text, e.user_confirmed_device_key_version, e.host_confirmed_at,
	       h.state, i.revoked_at, r.revoked_at, i.owner_user_id::text, i.public_key_thumbprint
		from enrollments e
		join hosts h on h.id = e.host_id
		join installations i on i.id = e.installation_id and i.host_id = e.host_id
		join runtimes r on r.id = e.runtime_id and r.installation_id = i.id
		where e.id = $1
		for update of e, h, i, r`, enrollmentID).Scan(
		&row.ID, &row.HostID, &row.InstallationID, &row.RuntimeID, &row.RequestedBy, &row.OrgID,
		&row.State, &row.CodeHash, &row.Expired, &row.ExpiresAt, &row.UserConfirmedBy,
		&row.UserConfirmedAt, &row.UserConfirmedDeviceID, &row.UserConfirmedDeviceKeyVersion, &row.HostConfirmedAt,
		&row.HostState, &row.InstallationRevoked, &row.RuntimeRevoked, &row.InstallationOwnerID, &row.InstallationKeyJKT)
	return row, err
}

func enrollmentConfirmation(row enrollmentRow) EnrollmentConfirmation {
	return EnrollmentConfirmation{
		EnrollmentID: row.ID, HostID: row.HostID, RuntimeID: row.RuntimeID, State: row.State, ExpiresAt: row.ExpiresAt,
		HostConfirmed: row.HostConfirmedAt.Valid, UserConfirmed: row.UserConfirmedBy.Valid,
	}
}

func nullStringValue(value sql.NullString) any {
	if !value.Valid {
		return nil
	}
	return value.String
}

func nullTimeValue(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}

func nullableUserID(present bool, userID string) any {
	if !present {
		return nil
	}
	return userID
}

func nullableTime(present bool, value time.Time) any {
	if !present {
		return nil
	}
	return value
}

func enrollmentWorkspaces(ctx context.Context, query enrollmentQuery, runtimeID string) ([]EnrollmentWorkspace, error) {
	rows, err := query.QueryContext(ctx, `select id::text, workspace_ref from workspaces where runtime_id = $1 order by workspace_ref`, runtimeID)
	if err != nil {
		return nil, ErrDatabaseUnavailable
	}
	defer rows.Close()
	workspaces := make([]EnrollmentWorkspace, 0)
	for rows.Next() {
		var workspace EnrollmentWorkspace
		if err := rows.Scan(&workspace.ID, &workspace.Reference); err != nil {
			return nil, ErrDatabaseUnavailable
		}
		workspaces = append(workspaces, workspace)
	}
	if err := rows.Err(); err != nil {
		return nil, ErrDatabaseUnavailable
	}
	return workspaces, nil
}

func enrollmentCodeHash(code string) ([]byte, error) {
	if len(code) != 43 {
		return nil, ErrEnrollmentInvalid
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(code)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != code {
		return nil, ErrEnrollmentInvalid
	}
	for index := range decoded {
		decoded[index] = 0
	}
	hash := sha256.Sum256([]byte(code))
	return hash[:], nil
}
