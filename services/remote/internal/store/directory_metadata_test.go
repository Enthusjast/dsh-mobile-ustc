package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDirectoryMetadataStrictVersionShapeAndUnicodeBounds(t *testing.T) {
	valid := `{"v":1,"title":"native title","workspace_title":"native workspace","title_source":"cached","title_as_of_seq":4}`
	var metadata DirectoryMetadata
	if err := json.Unmarshal([]byte(valid), &metadata); err != nil || !metadata.Valid() {
		t.Fatal("valid native hint rejected", err)
	}
	for _, invalid := range []string{
		strings.Replace(valid, `"v":1`, `"v":2`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"v":1`, 1),
		strings.Replace(valid, `"v":1`, `"v":1,"cwd":"/private"`, 1),
		strings.Replace(valid, `"title":"native title"`, `"title":null`, 1),
		strings.Replace(valid, `"title":"native title"`, `"title":"bad\nname"`, 1),
		strings.Replace(valid, `"title":"native title"`, `"title":"\ud800"`, 1),
		strings.Replace(valid, `"title":"native title"`, `"title":"\u202espoof"`, 1),
		strings.Replace(valid, `"title":"native title"`, `"title":"`+strings.Repeat("x", 257)+`"`, 1),
		strings.Replace(valid, `"title":"native title"`, `"title":"`+strings.Repeat("😀", 129)+`"`, 1),
		strings.Replace(valid, `,"title_source":"cached"`, ``, 1),
		strings.Replace(valid, `"title_as_of_seq":4`, `"title_as_of_seq":9007199254740992`, 1),
	} {
		if json.Unmarshal([]byte(invalid), &metadata) == nil {
			t.Fatal("invalid metadata accepted", invalid)
		}
	}
	for _, name := range []string{strings.Repeat("😀", 128), strings.Repeat("中", 256)} {
		if !validDirectoryName(&name) {
			t.Fatal("bounded UTF16 name rejected")
		}
	}
	if json.Unmarshal([]byte(`{"v":1,"title":null,"workspace_title":null,"title_source":null,"title_as_of_seq":null}`), &metadata) != nil {
		t.Fatal("authoritative deletion rejected")
	}
}

func TestDirectoryMetadataActionsAreExplicitAndCannotEnterViewerForkScopes(t *testing.T) {
	for _, role := range []string{"viewer", "operator"} {
		old := RuntimeGrantInput{Role: role, Scope: GrantScope{Actions: []string{"session.list"}, Workspaces: []string{}, Sessions: []string{}}}
		normalized, err := NormalizeRuntimeGrantInput(old, time.Now())
		if err != nil || len(normalized.Scope.Actions) != 1 || normalized.Scope.Actions[0] != "session.list" {
			t.Fatal("old scope expanded", normalized, err)
		}
		old.Scope.Actions = []string{"session.list", "session.metadata.read", "session.changes.read"}
		if _, err := NormalizeRuntimeGrantInput(old, time.Now()); err != nil {
			t.Fatal("explicit read actions rejected", err)
		}
	}
	if _, err := NormalizeTicketScope("viewer", GrantScope{Actions: []string{"session.fork"}, Workspaces: []string{}, Sessions: []string{}}); err == nil {
		t.Fatal("viewer gained fork action")
	}
}
