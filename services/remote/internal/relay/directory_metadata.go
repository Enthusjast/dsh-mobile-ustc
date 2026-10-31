package relay

import "dsh-mobile-ustc/services/remote/internal/store"

const directoryMetadataCapability = store.DirectoryMetadataCapability

// The version is negotiated independently from the legacy catalog capability.
func validateDirectoryCatalogMetadata(version *int, items []store.SessionCatalogItem, enabled bool) bool {
	if version != nil && (!enabled || *version != 1) {
		return false
	}
	for _, item := range items {
		if version == nil {
			if item.Metadata != nil {
				return false
			}
			continue
		}
		if item.Metadata == nil || !item.Metadata.Valid() {
			return false
		}
		if item.WorkspaceID == nil && item.Metadata.WorkspaceTitle != nil {
			return false
		}
		if item.State == "unavailable" && (item.Metadata.Title != nil || item.Metadata.WorkspaceTitle != nil) {
			return false
		}
	}
	return true
}
