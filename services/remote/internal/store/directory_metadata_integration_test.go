package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDirectoryNamesRequireOptInAndCurrentExplicitAction(t *testing.T) {
	ctx, database, proof := sessionDirectoryFixture(t)
	actor := UserIdentity{Issuer: "https://id.example.edu", Subject: "owner-subject"}
	metadata := `{"v":1,"title":"native title","workspace_title":"native workspace","title_source":"cached","title_as_of_seq":4}`
	if _, err := database.DB.ExecContext(ctx, `update sessions set directory_metadata=$1::jsonb where id='11111111-9999-4999-8999-999999999999'`, metadata); err != nil {
		t.Fatal(err)
	}
	for _, names := range []bool{false, true} {
		page, err := database.sessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 100, "", names)
		if err != nil || len(page.Items) != 4 {
			t.Fatal("list access lost without names action", page, err)
		}
		for _, item := range page.Items {
			if item.Metadata != nil {
				t.Fatal("old grant exposed names")
			}
		}
	}
	if _, err := database.DB.ExecContext(ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.list","session.metadata.read"]'),grant_version=grant_version+1 where runtime_id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	legacy, err := database.SessionDirectory(ctx, actor, managingDevice, proof, directoryRuntime, 100, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(legacy)
	if strings.Contains(string(raw), `"metadata"`) || strings.Contains(string(raw), "native title") {
		t.Fatal("legacy wire shape expanded")
	}
	modern, err := database.SessionDirectoryNames(ctx, actor, managingDevice, proof, directoryRuntime, 1, "")
	if err != nil || len(modern.Items) != 1 || modern.Items[0].Metadata == nil || *modern.Items[0].Metadata.Title != "native title" || modern.NextCursor == nil {
		t.Fatal("explicit projection missing", modern, err)
	}
	if _, err := database.DB.ExecContext(ctx, `update runtime_grants set scope=jsonb_set(scope,'{actions}','["session.list"]'),grant_version=grant_version+1 where runtime_id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	withdrawn, err := database.SessionDirectoryNames(ctx, actor, managingDevice, proof, directoryRuntime, 100, "")
	if err != nil || len(withdrawn.Items) != 4 {
		t.Fatal("metadata withdrawal removed ordinary access", withdrawn, err)
	}
	for _, item := range withdrawn.Items {
		if item.Metadata != nil {
			t.Fatal("withdrawn metadata persisted in response")
		}
	}
}

func TestReplacementRuntimeClearsPreviousProducerNamesButOfflineKeepsRegisteredHints(t *testing.T) {
	ctx, database, _ := sessionDirectoryFixture(t)
	metadata := `{"v":1,"title":"old title","workspace_title":"old workspace","title_source":"cached","title_as_of_seq":4}`
	if _, err := database.DB.ExecContext(ctx, `update sessions set directory_metadata=$1::jsonb where runtime_id=$2`, metadata, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	const registeredNames = `select coalesce(jsonb_object_agg(id::text,directory_metadata),'{}'::jsonb)::text from sessions where runtime_id=$1 and directory_metadata is not null`
	var before string
	if err := database.DB.QueryRowContext(ctx, registeredNames, directoryRuntime).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := database.DB.ExecContext(ctx, `update runtimes set connection_id=null where id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	var offline string
	if err := database.DB.QueryRowContext(ctx, registeredNames, directoryRuntime).Scan(&offline); err != nil || offline != before {
		t.Fatal("offline transition changed registered hints", offline, err)
	}
	if _, err := database.DB.ExecContext(ctx, `update runtimes set connection_id='aaaaaaaa-8888-4888-8888-aaaaaaaaaaaa' where id=$1`, directoryRuntime); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := database.DB.QueryRowContext(ctx, `select count(*) from sessions where runtime_id=$1 and directory_metadata is not null`, directoryRuntime).Scan(&count); err != nil || count != 0 {
		t.Fatal("replacement retained old producer names", count, err)
	}
}

func TestCatalogNullLegacyAndOmittedRowsClearRegisteredNames(t *testing.T) {
	ctx, database, _ := sessionDirectoryFixture(t)
	connection := RuntimeConnection{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", RuntimeID: directoryRuntime,
		RuntimeEpoch: "aaaaaaaa-7777-4777-8777-aaaaaaaaaaaa", ConnectionID: "aaaaaaaa-8888-4888-8888-aaaaaaaaaaaa"}
	if _, err := database.DB.ExecContext(ctx, `update runtimes set epoch=$1,connection_id=$2,connection_key_version=1 where id=$3`, connection.RuntimeEpoch, connection.ConnectionID, connection.RuntimeID); err != nil {
		t.Fatal(err)
	}
	session, err := MobileSessionID(directoryRuntime, "metadata-native-fixture")
	if err != nil {
		t.Fatal(err)
	}
	workspace, title, source, cut := "77777777-7777-4777-8777-777777777777", "native title", "cached", int64(4)
	item := SessionCatalogItem{SessionID: session, DSHSessionID: "metadata-native-fixture", WorkspaceID: &workspace, State: "available", LastPersistedSeq: 7}
	publish := func(t *testing.T) {
		t.Helper()
		item.Metadata = &DirectoryMetadata{Version: 1, Title: &title, WorkspaceTitle: &title, TitleSource: &source, TitleAsOfSeq: &cut}
		if err := database.SyncRealtimeSessionCatalog(ctx, connection, 1, false, []SessionCatalogItem{item}); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"null", "legacy", "missing-snapshot", "unavailable"} {
		t.Run(mode, func(t *testing.T) {
			publish(t)
			withdrawn := item
			switch mode {
			case "null":
				withdrawn.Metadata = &DirectoryMetadata{Version: 1}
			case "legacy":
				withdrawn.Metadata = nil
			case "unavailable":
				withdrawn.Metadata = &DirectoryMetadata{Version: 1}
				withdrawn.State = "unavailable"
				withdrawn.WorkspaceID = nil
				withdrawn.LastPersistedSeq = -1
			}
			items := []SessionCatalogItem{withdrawn}
			if mode == "missing-snapshot" {
				items = nil
			}
			if err := database.SyncRealtimeSessionCatalog(ctx, connection, 1, mode == "missing-snapshot", items); err != nil {
				t.Fatal(err)
			}
			var retained bool
			if err := database.DB.QueryRowContext(ctx, `select coalesce(directory_metadata->>'title','')<>'' or coalesce(directory_metadata->>'workspace_title','')<>'' from sessions where id=$1`, session).Scan(&retained); err != nil || retained {
				t.Fatal("authoritative withdrawal retained names", mode, err)
			}
		})
	}
}
