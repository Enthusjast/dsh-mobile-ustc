package releases

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	_, source, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../deploy/android/releases.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

var actor = Actor{"22222222-2222-4222-8222-222222222222", "33333333-3333-4333-8333-333333333333", "11111111-1111-4111-8111-111111111111"}
var request = Request{1, 1, 26}

func TestCatalogSelectionMatchesCrossLanguageGolden(t *testing.T) {
	catalog, err := Parse(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	result, err := catalog.Latest(actor, request)
	if err != nil || result.Release == nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	golden, err := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../contracts/golden/app-release-selection.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := json.Marshal(result)
	var expected, actual any
	_ = json.Unmarshal(golden, &expected)
	_ = json.Unmarshal(got, &actual)
	want, _ := json.Marshal(expected)
	normalized, _ := json.Marshal(actual)
	if string(want) != string(normalized) {
		t.Fatal("release selection drifted from golden", string(got))
	}
	*result.Release.RolloutBasisPoints = 0
	again, _ := catalog.Latest(actor, request)
	if again.Release == nil || *again.Release.RolloutBasisPoints != 10000 {
		t.Fatal("caller changed catalog policy")
	}
}

func TestCatalogRejectsAmbiguousOrUntrustedPublication(t *testing.T) {
	raw := string(fixture(t))
	for name, bad := range map[string]string{
		"duplicate":             strings.Replace(raw, `"version_code": 2`, `"version_code": 2, "version_code": 3`, 1),
		"unknown":               strings.Replace(raw, `"v": 1`, `"v": 1, "force_install": true`, 1),
		"missing rollout":       strings.Replace(raw, `"rollout_basis_points": 10000,`, "", 1),
		"null rollout":          strings.Replace(raw, `"rollout_basis_points": 10000`, `"rollout_basis_points": null`, 1),
		"overflow rollout":      strings.Replace(raw, `"rollout_basis_points": 10000`, `"rollout_basis_points": 10001`, 1),
		"unsigned origin":       strings.Replace(raw, `https://updates.example.invalid/android/`, `https://attacker.example/android/`, 1),
		"http":                  strings.ReplaceAll(raw, "https://", "http://"),
		"credentials":           strings.Replace(raw, `https://updates.example.invalid/android/`, `https://user:password@updates.example.invalid/android/`, 1),
		"query":                 strings.Replace(raw, `dsh-mobile-2.apk`, `dsh-mobile-2.apk?token=secret`, 1),
		"fragment":              strings.Replace(raw, `dsh-mobile-2.apk`, `dsh-mobile-2.apk#`, 1),
		"path":                  strings.Replace(raw, `/android/dsh-mobile-2.apk`, `/android/../dsh-mobile-2.apk`, 1),
		"encoded path":          strings.Replace(raw, `/android/dsh-mobile-2.apk`, `/android/%2e%2e/dsh-mobile-2.apk`, 1),
		"wrong package":         strings.Replace(raw, `"package_name": "cn.edu.ustc.dsh.mobile"`, `"package_name": "cn.edu.other"`, 1),
		"unsupported target":    strings.Replace(raw, `"maximum": 2`, `"maximum": 1`, 1),
		"wrong protocol window": strings.Replace(raw, `"minimum_protocol_version": 1`, `"minimum_protocol_version": 2`, 1),
		"no target org":         strings.Replace(raw, `"organization_ids": ["11111111-1111-4111-8111-111111111111"]`, `"organization_ids": []`, 1),
		"wrong hash":            strings.Replace(raw, strings.Repeat("a", 64), strings.Repeat("A", 64), 1),
		"trailing":              raw + "{}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(bad)); err == nil {
				t.Fatal("invalid catalog accepted")
			}
		})
	}
}

func TestLatestEnforcesVersionOrganizationProtocolAndAndroidEligibility(t *testing.T) {
	catalog, _ := Parse(fixture(t))
	for name, test := range map[string]struct {
		actor     Actor
		request   Request
		supported bool
	}{
		"already installed":    {actor, Request{2, 1, 26}, true},
		"newer client":         {actor, Request{3, 1, 26}, false},
		"another organization": {Actor{actor.UserID, actor.DeviceID, "44444444-4444-4444-8444-444444444444"}, request, true},
	} {
		t.Run(name, func(t *testing.T) {
			selection, err := catalog.Latest(test.actor, test.request)
			if err != nil || selection.Release != nil || selection.CurrentSupported != test.supported {
				t.Fatal("incorrect eligibility", err, selection)
			}
		})
	}
	for _, r := range []Request{{0, 1, 26}, {1, 2, 26}, {1, 1, 25}} {
		if _, err := catalog.Latest(actor, r); err == nil {
			t.Fatal("invalid client claims accepted")
		}
	}
	base := string(fixture(t))
	for _, changed := range []string{
		strings.Replace(base, `"minimum_android_api": 26`, `"minimum_android_api": 35`, 1),
		strings.Replace(strings.Replace(base, `"minimum_protocol_version": 1`, `"minimum_protocol_version": 2`, 1), `"maximum_protocol_version": 1`, `"maximum_protocol_version": 2`, 1),
	} {
		future, err := Parse([]byte(changed))
		if err != nil {
			t.Fatal(err)
		}
		result, err := future.Latest(actor, request)
		if err != nil || result.Release != nil {
			t.Fatal("incompatible release offered", err)
		}
	}
}

func TestLatestChoosesHighestEligiblePublicationAndAllowsWithdrawal(t *testing.T) {
	var config deployment
	if err := json.Unmarshal(fixture(t), &config); err != nil {
		t.Fatal(err)
	}
	config.ClientWindow.Maximum = 3
	newest := config.Publications[0]
	newest.Release.ID = "88888888-8888-4888-8888-888888888888"
	newest.Release.VersionCode = 3
	zero := 0
	newest.Release.RolloutBasisPoints = &zero
	config.Publications = append(config.Publications, newest)
	selectVersion := func(want int64) {
		raw, _ := json.Marshal(config)
		catalog, err := Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		result, err := catalog.Latest(actor, request)
		if err != nil || result.Release == nil || result.Release.VersionCode != want {
			t.Fatal("wrong release priority", err)
		}
	}
	selectVersion(2)
	zero = 10000
	selectVersion(3)
	config.Publications[0], config.Publications[1] = config.Publications[1], config.Publications[0]
	selectVersion(3)
	config.Publications = []publication{}
	raw, _ := json.Marshal(config)
	catalog, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	result, err := catalog.Latest(actor, request)
	if err != nil || result.Release != nil || !result.CurrentSupported {
		t.Fatal("withdrawal changed client support", err)
	}
}

func TestRolloutIsStableAndExpandsWithoutChangingExistingDeviceAssignment(t *testing.T) {
	base := string(fixture(t))
	load := func(points int) *Catalog {
		catalog, err := Parse([]byte(strings.Replace(base, `"rollout_basis_points": 10000`, fmt.Sprintf(`"rollout_basis_points": %d`, points), 1)))
		if err != nil {
			t.Fatal(err)
		}
		return catalog
	}
	zero, small, large := load(0), load(1000), load(5000)
	count := 0
	for i := 0; i < 1000; i++ {
		device := actor
		device.DeviceID = fmt.Sprintf("%08x-3333-4333-8333-333333333333", i)
		none, _ := zero.Latest(device, request)
		a, _ := small.Latest(device, request)
		again, _ := small.Latest(device, request)
		b, _ := large.Latest(device, request)
		if none.Release != nil || (a.Release != nil) != (again.Release != nil) || a.Release != nil && b.Release == nil {
			t.Fatal("unstable or nonmonotonic rollout")
		}
		if a.Release != nil {
			count++
		}
	}
	if count < 60 || count > 140 {
		t.Fatal("unexpected deterministic rollout distribution", count)
	}
}
