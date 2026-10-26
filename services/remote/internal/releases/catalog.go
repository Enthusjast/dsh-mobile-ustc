// Package releases selects public APK metadata. Rollout is a deployment choice,
// never authority to read a runtime, content, credentials or signing keys.
package releases

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"dsh-mobile-ustc/services/remote/internal/canonical"
)

const MaxAPKBytes int64 = 512 << 20
const maxVersion int64 = 9007199254740991
const ProtocolVersion int64 = 1

var ErrInvalid = errors.New("releases: invalid configuration or request")
var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var packageName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

type VersionWindow struct {
	Minimum int64 `json:"minimum"`
	Maximum int64 `json:"maximum"`
}

type Release struct {
	ID                     string `json:"release_id"`
	VersionCode            int64  `json:"version_code"`
	VersionName            string `json:"version_name"`
	PackageName            string `json:"package_name"`
	SHA256                 string `json:"sha256"`
	SizeBytes              int64  `json:"size_bytes"`
	SigningCertificate     string `json:"signing_cert_sha256"`
	DownloadURL            string `json:"download_url"`
	MinimumProtocolVersion int64  `json:"minimum_protocol_version"`
	MaximumProtocolVersion int64  `json:"maximum_protocol_version"`
	MinimumAndroidAPI      int64  `json:"minimum_android_api"`
	RolloutBasisPoints     *int   `json:"rollout_basis_points"`
	ReleaseNotes           string `json:"release_notes"`
}

type publication struct {
	Release       Release  `json:"release"`
	Organizations []string `json:"organization_ids"`
}
type deployment struct {
	Version         int           `json:"v"`
	Package         string        `json:"package_name"`
	DownloadOrigins []string      `json:"download_origins"`
	ClientWindow    VersionWindow `json:"supported_client_versions"`
	Publications    []publication `json:"publications"`
}

// Catalog is an immutable startup snapshot. Changing publication, withdrawal or
// rollout policy requires validated configuration and a service restart.
type Catalog struct{ config deployment }

type Actor struct{ UserID, DeviceID, OrganizationID string }
type Request struct{ VersionCode, ProtocolVersion, AndroidAPI int64 }
type Selection struct {
	Version            int           `json:"v"`
	PackageName        string        `json:"package_name"`
	ProtocolVersion    int64         `json:"protocol_version"`
	CurrentVersionCode int64         `json:"current_version_code"`
	CurrentSupported   bool          `json:"current_supported"`
	ClientWindow       VersionWindow `json:"supported_client_versions"`
	Release            *Release      `json:"release"`
}

func Parse(raw []byte) (*Catalog, error) {
	if _, err := canonical.Object(raw); err != nil {
		return nil, ErrInvalid
	}
	var config deployment
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || decoder.Decode(new(any)) != io.EOF || config.Version != 1 ||
		!packageName.MatchString(config.Package) || len(config.Package) > 255 ||
		config.ClientWindow.Minimum < 1 || config.ClientWindow.Maximum < config.ClientWindow.Minimum || config.ClientWindow.Maximum > maxVersion ||
		len(config.DownloadOrigins) < 1 || len(config.DownloadOrigins) > 8 || config.Publications == nil || len(config.Publications) > 64 {
		return nil, ErrInvalid
	}
	origins := make(map[string]bool)
	for _, origin := range config.DownloadOrigins {
		u := httpsURL(origin)
		if u == nil || u.Path != "" || origins[origin] {
			return nil, ErrInvalid
		}
		origins[origin] = true
	}
	ids, versions := make(map[string]bool), make(map[int64]bool)
	for _, entry := range config.Publications {
		r := entry.Release
		u := httpsURL(r.DownloadURL)
		if !uuid.MatchString(r.ID) || ids[r.ID] || versions[r.VersionCode] || r.PackageName != config.Package ||
			r.VersionCode < config.ClientWindow.Minimum || r.VersionCode > config.ClientWindow.Maximum ||
			!text(r.VersionName, 64, false) || !text(r.ReleaseNotes, 8192, true) ||
			!digest.MatchString(r.SHA256) || !digest.MatchString(r.SigningCertificate) || r.SizeBytes < 1 || r.SizeBytes > MaxAPKBytes ||
			r.MinimumProtocolVersion < 1 || r.MaximumProtocolVersion < r.MinimumProtocolVersion || r.MaximumProtocolVersion > 32 ||
			r.MinimumAndroidAPI < 26 || r.MinimumAndroidAPI > 100 || r.RolloutBasisPoints == nil || *r.RolloutBasisPoints < 0 || *r.RolloutBasisPoints > 10000 ||
			u == nil || !origins[u.Scheme+"://"+u.Host] || u.Path == "" || u.Path == "/" || path.Clean(u.Path) != u.Path ||
			len(entry.Organizations) < 1 || len(entry.Organizations) > 128 {
			return nil, ErrInvalid
		}
		organizations := make(map[string]bool)
		for _, id := range entry.Organizations {
			if !uuid.MatchString(id) || organizations[id] {
				return nil, ErrInvalid
			}
			organizations[id] = true
		}
		ids[r.ID], versions[r.VersionCode] = true, true
	}
	slices.SortFunc(config.Publications, func(a, b publication) int {
		if a.Release.VersionCode > b.Release.VersionCode {
			return -1
		}
		if a.Release.VersionCode < b.Release.VersionCode {
			return 1
		}
		return 0
	})
	return &Catalog{config: config}, nil
}

// Latest assumes the caller has freshly authorized this exact actor. Client
// version/API claims select metadata only; they create no authorization.
func (catalog *Catalog) Latest(actor Actor, request Request) (Selection, error) {
	if catalog == nil || !uuid.MatchString(actor.UserID) || !uuid.MatchString(actor.DeviceID) || !uuid.MatchString(actor.OrganizationID) ||
		request.VersionCode < 1 || request.VersionCode > maxVersion || request.ProtocolVersion != ProtocolVersion || request.AndroidAPI < 26 || request.AndroidAPI > 100 {
		return Selection{}, ErrInvalid
	}
	result := Selection{Version: 1, PackageName: catalog.config.Package, ProtocolVersion: ProtocolVersion, CurrentVersionCode: request.VersionCode,
		ClientWindow: catalog.config.ClientWindow, CurrentSupported: request.VersionCode >= catalog.config.ClientWindow.Minimum && request.VersionCode <= catalog.config.ClientWindow.Maximum}
	for _, entry := range catalog.config.Publications {
		r := entry.Release
		if r.VersionCode <= request.VersionCode || !slices.Contains(entry.Organizations, actor.OrganizationID) || request.AndroidAPI < r.MinimumAndroidAPI ||
			request.ProtocolVersion < r.MinimumProtocolVersion || request.ProtocolVersion > r.MaximumProtocolVersion || bucket(actor, r.ID) >= *r.RolloutBasisPoints {
			continue
		}
		// A returned metadata snapshot cannot mutate the catalog's rollout policy.
		points := *r.RolloutBasisPoints
		r.RolloutBasisPoints = &points
		result.Release = &r
		break
	}
	return result, nil
}

func bucket(actor Actor, release string) int {
	sum := sha256.Sum256([]byte("dsh-mobile-update-rollout-v1\x00" + actor.OrganizationID + "\x00" + actor.UserID + "\x00" + actor.DeviceID + "\x00" + release))
	return int(binary.BigEndian.Uint64(sum[:8]) % 10000)
}

func httpsURL(raw string) *url.URL {
	if len(raw) == 0 || len(raw) > 2048 || strings.ContainsRune(raw, '\\') || strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r >= 127 }) {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawPath != "" || strings.ToLower(u.Host) != u.Host || u.String() != raw {
		return nil
	}
	return u
}

func text(value string, limit int, multiline bool) bool {
	return len(value) <= limit && strings.TrimSpace(value) != "" && !strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) && !(multiline && (r == '\n' || r == '\t'))
	})
}
