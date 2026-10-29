package coldarchive

import (
	"encoding/hex"
	"strings"
	"time"

	"dsh-mobile-ustc/services/remote/internal/auth"
)

// ValidateRecoveryLineage checks bounded released recovery facts and a path
// from source to target. It never interprets transaction IDs across clusters.
func ValidateRecoveryLineage(recoveries []Recovery, source, target string, notAfter time.Time) error {
	return ValidateRecoveryPaths(recoveries, []RecoveryPath{{Source: source, Target: target}}, notAfter)
}

type RecoveryPath struct{ Source, Target string }

// ValidateRecoveryPaths validates the graph once before checking bounded paths.
func ValidateRecoveryPaths(recoveries []Recovery, paths []RecoveryPath, notAfter time.Time) error {
	if recoveries == nil || len(recoveries) > MaxRecoveries || len(paths) == 0 || len(paths) > 129 || notAfter.IsZero() {
		return ErrInvalid
	}
	for _, path := range paths {
		if !UUID(path.Source) || !UUID(path.Target) {
			return ErrInvalid
		}
	}
	bySource := map[string][]string{}
	seenIDs, seenTargets := map[string]bool{}, map[string]bool{}
	for _, recovery := range recoveries {
		if !UUID(recovery.ID) || seenIDs[recovery.ID] || !UUID(recovery.SourceEpoch) || !UUID(recovery.TargetEpoch) || recovery.SourceEpoch == recovery.TargetEpoch || seenTargets[recovery.TargetEpoch] ||
			recovery.PreparedAt.IsZero() || recovery.ReleasedAt.Before(recovery.PreparedAt) || recovery.ReleasedAt.After(notAfter) || len(recovery.AuthoritySHA256) != 64 ||
			len(recovery.Counts) == 0 || auth.ValidateJSONObject(recovery.Counts) != nil {
			return ErrInvalid
		}
		if _, err := hex.DecodeString(recovery.AuthoritySHA256); err != nil || recovery.AuthoritySHA256 != strings.ToLower(recovery.AuthoritySHA256) {
			return ErrInvalid
		}
		seenIDs[recovery.ID], seenTargets[recovery.TargetEpoch] = true, true
		bySource[recovery.SourceEpoch] = append(bySource[recovery.SourceEpoch], recovery.TargetEpoch)
	}
	visited := map[string]uint8{}
	var acyclic func(string) bool
	acyclic = func(epoch string) bool {
		if visited[epoch] == 1 {
			return false
		}
		if visited[epoch] == 2 {
			return true
		}
		visited[epoch] = 1
		for _, next := range bySource[epoch] {
			if !acyclic(next) {
				return false
			}
		}
		visited[epoch] = 2
		return true
	}
	for epoch := range bySource {
		if !acyclic(epoch) {
			return ErrInvalid
		}
	}
	for _, path := range paths {
		seen := map[string]bool{path.Source: true}
		queue := []string{path.Source}
		for len(queue) > 0 && !seen[path.Target] {
			current := queue[0]
			queue = queue[1:]
			for _, next := range bySource[current] {
				if !seen[next] {
					seen[next] = true
					queue = append(queue, next)
				}
			}
		}
		if !seen[path.Target] {
			return ErrInvalid
		}
	}
	return nil
}
