package httpapi

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDirectoryMetadataProjectionRejectsUnknownVersionsAndSelectors(t *testing.T) {
	for _, query := range []string{"", "?limit=2&cursor=opaque", "?projection=names.v1", "?projection=names.v1&limit=100"} {
		request := httptest.NewRequest("GET","https://relay.example/v1/runtimes/id/session-directory"+query,nil)
		original := request.URL.RawQuery
		_, _, names, valid := sessionDirectoryPageQuery(request)
		if !valid || names != strings.Contains(query,"projection=names.v1") || request.URL.RawQuery != original { t.Fatal("valid projection changed/failed",query) }
	}
	for _, query := range []string{"?projection=names.v2", "?projection=", "?projection=names.v1&projection=names.v1", "?projection=names.v1&user_id=attacker", "?projection=names.v1&limit=01", "?projection=names.v1&refresh=1", "?projection=%zz"} {
		request := httptest.NewRequest("GET","https://relay.example/v1/runtimes/id/session-directory"+query,nil)
		if _, _, _, valid := sessionDirectoryPageQuery(request); valid { t.Fatal("unknown projection/selector accepted",query) }
	}
	request := httptest.NewRequest("GET","https://relay.example/v1/runtimes/id/session-directory?projection=names.v1",strings.NewReader("{}"))
	if _, _, _, valid := sessionDirectoryPageQuery(request); valid { t.Fatal("GET body accepted") }
}
