package relay

import (
	"testing"

	"dsh-mobile-ustc/services/remote/internal/store"
)

func TestCatalogMetadataRequiresNegotiatedVersionAndCompleteItems(t *testing.T) {
	version, other := 1, 2
	metadata := &store.DirectoryMetadata{Version: 1}
	legacy := []store.SessionCatalogItem{{State: "available"}}
	modern := []store.SessionCatalogItem{{State: "available", Metadata: metadata}}
	if !validateDirectoryCatalogMetadata(nil, legacy, false) {
		t.Fatal("legacy catalog rejected")
	}
	if !validateDirectoryCatalogMetadata(&version, modern, true) {
		t.Fatal("negotiated null projection rejected")
	}
	for _, sample := range []struct {
		version *int
		items   []store.SessionCatalogItem
		enabled bool
	}{
		{&version, modern, false}, {&other, modern, true}, {nil, modern, true}, {&version, legacy, true},
	} {
		if validateDirectoryCatalogMetadata(sample.version, sample.items, sample.enabled) {
			t.Fatal("unnegotiated/partial metadata accepted")
		}
	}
	title := "deleted title"
	modern[0].State = "unavailable"
	modern[0].Metadata = &store.DirectoryMetadata{Version: 1, WorkspaceTitle: &title}
	if validateDirectoryCatalogMetadata(&version, modern, true) {
		t.Fatal("tombstone retained a title")
	}
}
