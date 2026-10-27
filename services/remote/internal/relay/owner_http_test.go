package relay

import "testing"

func TestPrivateHTTPRouteAllowlistRejectsGenericProxyTargets(t *testing.T) {
	const id = "aaaaaaaa-1111-4111-8111-111111111111"
	for _, test := range []struct{ method, path, kind string }{
		{"POST", "/v1/approvals/" + id + "/decisions", "approval"},
		{"GET", "/v1/host-files/" + id + "/content", "host_file"},
		{"GET", "/v1/files/" + id, "file_status"},
		{"GET", "/v1/approvals/" + id + "/decisions", ""},
		{"POST", "/v1/devices", ""},
		{"DELETE", "/v1/devices/" + id, ""},
		{"GET", "/v1/files/" + id + "/content", ""},
		{"GET", "https://example.com/v1/files/" + id, ""},
		{"GET", "/v1/files/../" + id, ""},
		{"GET", "/v1/files/" + id + "?query=1", ""},
		{"GET", "/v1/files/%61" + id[1:], ""},
		{"GET", "/healthz", ""},
	} {
		if kind, resource := OwnerHTTPResource(test.method, test.path); kind != test.kind || kind != "" && resource != id {
			t.Fatalf("unexpected route %s %s => %s", test.method, test.path, kind)
		}
	}
}
