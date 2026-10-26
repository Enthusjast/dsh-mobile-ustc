package push

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

var projectID = regexp.MustCompile(`^([a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$`)
var packageID = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*(\.[a-zA-Z][a-zA-Z0-9_]*)+$`)

type FCM struct {
	project, packageName, endpoint string
	tokens                         AccessTokens
	client                         *http.Client
}

func (*FCM) String() string   { return "FCMSender" }
func (*FCM) GoString() string { return "FCMSender" }
func NewFCM(project, application string, tokens AccessTokens, client *http.Client) (*FCM, error) {
	if !projectID.MatchString(project) || !packageID.MatchString(application) || len(application) > 255 || tokens == nil {
		return nil, ErrInvalid
	}
	return &FCM{project: project, packageName: application, endpoint: "https://fcm.googleapis.com/v1/projects/" + project + "/messages:send", tokens: tokens, client: secureClient(client)}, nil
}
func retryAfter(header string, now time.Time, minimum time.Duration) time.Duration {
	if seconds, err := strconv.ParseInt(header, 10, 64); err == nil && seconds >= 0 {
		if seconds > 3600 {
			return time.Hour
		}
		return max(minimum, time.Duration(seconds)*time.Second)
	}
	if date, err := http.ParseTime(header); err == nil && date.After(now) && date.Sub(now) <= time.Hour {
		return max(minimum, date.Sub(now))
	}
	return minimum
}
func (sender *FCM) Send(ctx context.Context, out Outbound, current func(context.Context) error) Result {
	ctx, cancel := context.WithDeadline(ctx, out.ExpiresAt)
	defer cancel()
	if out.Provider != "fcm" || !FID(out.Address) || !UUID(out.BindingID) || current == nil {
		return Result{State: Failed, Code: "invalid_envelope"}
	}
	data := map[string]string{"v": "1", "binding_id": out.BindingID, "expires_at": out.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z")}
	priority := "HIGH"
	switch out.Kind {
	case "challenge":
		if !Secret(out.Challenge) || out.NotificationID != "" {
			return Result{State: Failed, Code: "invalid_envelope"}
		}
		data["kind"] = "registration_challenge"
		data["challenge"] = out.Challenge
		priority = "NORMAL"
	case "approval", "question", "timed_question":
		if !UUID(out.NotificationID) || out.Challenge != "" {
			return Result{State: Failed, Code: "invalid_envelope"}
		}
		data["kind"] = "interaction"
		data["notification_id"] = out.NotificationID
	default:
		return Result{State: Failed, Code: "invalid_envelope"}
	}
	token, err := sender.tokens.Token(ctx)
	if err != nil {
		return Result{State: Retry, Code: "provider_auth_unavailable", RetryAfter: 30 * time.Second}
	}
	if err := current(ctx); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return Result{State: Retry, Code: "metadata_unavailable", RetryAfter: 5 * time.Second}
		}
		return Result{State: Expired, Code: "authority_changed"}
	}
	ttl := int64(time.Until(out.ExpiresAt) / time.Second)
	if ttl < 1 || ttl > 3600 {
		return Result{State: Expired, Code: "expired"}
	}
	// Data only, no session collapse key and no automatically displayed private content.
	body, _ := json.Marshal(map[string]any{"message": map[string]any{"fid": out.Address, "data": data,
		"android": map[string]any{"priority": priority, "ttl": strconv.FormatInt(ttl, 10) + "s", "restricted_package_name": sender.packageName}}})
	request, err := http.NewRequestWithContext(ctx, "POST", sender.endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{State: Failed, Code: "invalid_envelope"}
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	response, err := sender.client.Do(request)
	if err != nil {
		return Result{State: Retry, Code: "provider_result_unknown", RetryAfter: 10 * time.Second}
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return Result{State: Failed, Code: "provider_redirect"}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, (16<<10)+1))
	defer clear(raw)
	if err != nil || len(raw) > 16<<10 || auth.ValidateJSONObject(raw) != nil {
		return Result{State: Retry, Code: "provider_result_unknown", RetryAfter: 10 * time.Second}
	}
	if response.StatusCode == 200 {
		var result struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(raw, &result) != nil || len(result.Name) < 1 || len(result.Name) > 1024 || !strings.HasPrefix(result.Name, "projects/") || !strings.Contains(result.Name, "/messages/") {
			return Result{State: Retry, Code: "provider_result_unknown", RetryAfter: 10 * time.Second}
		}
		digest := sha256.Sum256([]byte(result.Name))
		return Result{State: Accepted, ProviderID: hex.EncodeToString(digest[:])}
	}
	var failure struct {
		Error struct {
			Details []struct {
				Type string `json:"@type"`
				Code string `json:"errorCode"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &failure)
	for _, detail := range failure.Error.Details {
		if detail.Type == "type.googleapis.com/google.firebase.fcm.v1.FcmError" && detail.Code == "UNREGISTERED" && response.StatusCode == 404 {
			return Result{State: InvalidEndpoint, Code: "provider_unregistered"}
		}
	}
	switch {
	case response.StatusCode == 401:
		if invalidator, ok := sender.tokens.(interface{ Invalidate(string) }); ok {
			invalidator.Invalidate(token)
		}
		return Result{State: Retry, Code: "provider_auth_unavailable", RetryAfter: 30 * time.Second}
	case response.StatusCode == 429:
		return Result{State: Retry, Code: "provider_throttled", RetryAfter: retryAfter(response.Header.Get("Retry-After"), time.Now(), time.Minute)}
	case response.StatusCode >= 500:
		return Result{State: Retry, Code: "provider_unavailable", RetryAfter: retryAfter(response.Header.Get("Retry-After"), time.Now(), 10*time.Second)}
	default:
		return Result{State: Failed, Code: "provider_rejected"}
	}
}
