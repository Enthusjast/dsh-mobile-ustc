package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRelayDirectoryFencesConnectionAndNodeReplacement(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, postgres.DB)
	newNode := func(id, origin string) (*ControlConsumer, *RelayDirectory) {
		t.Helper()
		consumer, err := postgres.NewControlConsumer(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		directory, err := consumer.NewRelayDirectory(ctx, origin)
		if err != nil {
			t.Fatal(err)
		}
		return consumer, directory
	}
	a, left := newNode(controlNodeA, "https://127.0.0.1:9011")
	_, right := newNode(controlNodeB, "https://127.0.0.1:9012")
	input := RuntimeConnectionInput{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", KeyVersion: 1,
		RuntimeID: "55555555-5555-4555-8555-555555555555", RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t),
		DSHVersion: "0.2.1-rc.2", ApplicationVersion: "directory-fixture", PluginVersion: "test", ProtocolVersion: 1}
	first, err := left.AttachRuntimeConnection(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	route, err := right.LookupRuntimeRoute(ctx, input.RuntimeID)
	if err != nil || route.RelayNode != left.RelayIdentity() || route.ConnectionID != first.ConnectionID || route.RuntimeEpoch != first.RuntimeEpoch {
		t.Fatal("foreign node cannot resolve exact owner", route, err)
	}
	if err := right.TouchRuntimeConnection(ctx, first.InstallationID, first.RuntimeID, first.RuntimeEpoch, first.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("foreign node touched another owner", err)
	}
	input.RuntimeEpoch, input.ConnectionID = approvalTestUUID(t), approvalTestUUID(t)
	second, err := right.AttachRuntimeConnection(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := left.TouchRuntimeConnection(ctx, first.InstallationID, first.RuntimeID, first.RuntimeEpoch, first.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("replaced connection renewed", err)
	}
	if err := left.DetachRuntimeConnection(ctx, first.InstallationID, first.RuntimeID, first.RuntimeEpoch, first.ConnectionID); err != nil {
		t.Fatal(err)
	}
	route, err = left.LookupRuntimeRoute(ctx, input.RuntimeID)
	if err != nil || route.RelayNode != right.RelayIdentity() || route.ConnectionID != second.ConnectionID {
		t.Fatal("old cleanup deleted new owner", route, err)
	}
	// A consumer replacement fences the entire previous node incarnation, even
	// while the old runtime metadata still looks recently connected.
	if err := a.Release(ctx); err != nil {
		t.Fatal(err)
	}
	newA, restarted := newNode(controlNodeA, "https://127.0.0.1:9013")
	if newA.generation == a.generation {
		t.Fatal("node generation reused")
	}
	if _, err := left.AttachRuntimeConnection(ctx, input); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("old node attached after takeover", err)
	}
	input.RuntimeEpoch, input.ConnectionID = approvalTestUUID(t), approvalTestUUID(t)
	third, err := restarted.AttachRuntimeConnection(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if err := left.DetachRuntimeConnection(ctx, third.InstallationID, third.RuntimeID, third.RuntimeEpoch, third.ConnectionID); err != nil {
		t.Fatal(err)
	}
	route, err = right.LookupRuntimeRoute(ctx, input.RuntimeID)
	if err != nil || route.ConnectionID != third.ConnectionID || route.RelayNode != restarted.RelayIdentity() {
		t.Fatal("fenced node removed new-generation route", route, err)
	}
	if err := restarted.DetachRuntimeConnection(ctx, third.InstallationID, third.RuntimeID, third.RuntimeEpoch, third.ConnectionID); err != nil {
		t.Fatal(err)
	}
	if _, err := right.LookupRuntimeRoute(ctx, input.RuntimeID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("detached route remained usable", err)
	}
}

func TestRelayDirectoryExpiryAndFailedAttachDoNotPublishOwnership(t *testing.T) {
	ctx, postgres := newPostgresIntegrationDatabase(t)
	seedGrantFixture(t, ctx, postgres.DB)
	consumer, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	directory, err := consumer.NewRelayDirectory(ctx, "https://127.0.0.1:9011")
	if err != nil {
		t.Fatal(err)
	}
	input := RuntimeConnectionInput{InstallationID: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", KeyVersion: 1, RuntimeID: "55555555-5555-4555-8555-555555555555", RuntimeEpoch: approvalTestUUID(t), ConnectionID: approvalTestUUID(t), DSHVersion: "0.2.1-rc.2", ApplicationVersion: "fixture", PluginVersion: "test", ProtocolVersion: 1}
	connection, err := directory.AttachRuntimeConnection(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	blocked, err := postgres.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer blocked.Rollback()
	if _, err := blocked.ExecContext(ctx, `select node_id from control_consumers where node_id=$1 for update`, controlNodeA); err != nil {
		t.Fatal(err)
	}
	deadline, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	input.RuntimeEpoch, input.ConnectionID = approvalTestUUID(t), approvalTestUUID(t)
	_, err = directory.AttachRuntimeConnection(deadline, input)
	cancel()
	if err == nil {
		t.Fatal("attach ignored node ownership lock")
	}
	if err := blocked.Rollback(); err != nil {
		t.Fatal(err)
	}
	route, err := directory.LookupRuntimeRoute(ctx, input.RuntimeID)
	if err != nil || route.ConnectionID != connection.ConnectionID {
		t.Fatal("failed transaction changed route", route, err)
	}
	if _, err := postgres.DB.ExecContext(ctx, `update control_consumers set lease_until=clock_timestamp()-interval '1 second' where node_id=$1`, controlNodeA); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.LookupRuntimeRoute(ctx, input.RuntimeID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("expired node route used", err)
	}
	if err := directory.TouchRuntimeConnection(ctx, connection.InstallationID, connection.RuntimeID, connection.RuntimeEpoch, connection.ConnectionID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("expired node renewed runtime", err)
	}
	if err := directory.ValidateRelayNode(ctx, controlNodeA, consumer.generation); !errors.Is(err, ErrControlConsumerFenced) {
		t.Fatal("expired tunnel sender accepted", err)
	}
	restarted, err := postgres.NewControlConsumer(ctx, controlNodeA)
	if err != nil {
		t.Fatal(err)
	}
	var origin *string
	if err := postgres.DB.QueryRowContext(ctx, `select relay_origin from control_consumers where node_id=$1`, controlNodeA).Scan(&origin); err != nil || origin != nil {
		t.Fatal("restart advertised previous endpoint", err)
	}
	fresh, err := restarted.NewRelayDirectory(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.LookupRuntimeRoute(ctx, input.RuntimeID); !errors.Is(err, ErrRuntimeConnectionStale) {
		t.Fatal("new generation inherited old route", err)
	}
}

func TestRelayOriginRejectsAmbientURLComponents(t *testing.T) {
	for _, origin := range []string{"http://127.0.0.1:9011", "https://user@node", "https://node/", "https://node?", "https://node?x=1", "https://node/#fragment", "https://node\n", "https://"} {
		if ValidRelayOrigin(origin) {
			t.Fatalf("accepted invalid origin %q", origin)
		}
	}
	for _, origin := range []string{"https://127.0.0.1:9011", "https://[::1]:9011", "https://relay.internal"} {
		if !ValidRelayOrigin(origin) {
			t.Fatalf("rejected origin %q", origin)
		}
	}
}
