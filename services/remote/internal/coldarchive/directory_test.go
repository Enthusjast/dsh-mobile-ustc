package coldarchive

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestDirectoryPublishesOnceWithoutOverwritingOrPlaintext(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	directory, err := OpenDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	key := testKey(t, 1)
	payload := examplePayload(t)
	salt, nonce, _ := Material()
	artifact, _, err := Seal(key, payload, salt, nonce)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(raw []byte) error { _, err := Open(key, raw, testDomain, testExport); return err }
	var workers sync.WaitGroup
	errorsSeen := make(chan error, 4)
	for range 4 {
		workers.Go(func() { errorsSeen <- directory.Publish(testExport, artifact, verify) })
	}
	workers.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatal("concurrent publication failed", err)
		}
	}
	stored, err := directory.Read(testExport)
	if err != nil || !bytes.Equal(stored, artifact) {
		t.Fatal("published artifact changed", err)
	}
	if bytes.Contains(stored, []byte("PRIVATE_ARCHIVE_BODY")) {
		t.Fatal("file contains plaintext")
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 {
		t.Fatal("publication left temporary files", err)
	}
	info, err := entries[0].Info()
	if err != nil || info.Mode().Perm()&0077 != 0 {
		t.Fatal("artifact permissions are too broad", err)
	}
	otherSalt, otherNonce, err := Material()
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := Seal(key, payload, otherSalt, otherNonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := directory.Publish(testExport, other, verify); !errors.Is(err, ErrConflict) {
		t.Fatal("different content replaced an existing artifact", err)
	}
	stored, err = directory.Read(testExport)
	if err != nil || !bytes.Equal(stored, artifact) {
		t.Fatal("conflict modified existing artifact", err)
	}
}

func TestDirectoryRejectsBroadPermissionsSymlinksAndCrossRootTargets(t *testing.T) {
	path := t.TempDir()
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirectory(path); err == nil {
		t.Fatal("public output directory accepted")
	}
	if err := os.Chmod(path, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenDirectory(link); err == nil {
		t.Fatal("symlinked root accepted")
	}
	directory, err := OpenDirectory(path)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if _, err := directory.Read("../outside"); !errors.Is(err, ErrInvalid) {
		t.Fatal("caller controlled artifact name", err)
	}
	key := testKey(t, 2)
	payload := examplePayload(t)
	salt, nonce, _ := Material()
	artifact, _, _ := Seal(key, payload, salt, nonce)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(path, testExport+".dshca")); err != nil {
		t.Fatal(err)
	}
	if err := directory.Publish(testExport, artifact, func([]byte) error { return nil }); err == nil {
		t.Fatal("existing symlink was accepted")
	}
	value, err := os.ReadFile(outside)
	if err != nil || string(value) != "original" {
		t.Fatal("publication changed a file outside the root", err)
	}
}

func TestKeyFileRequiresOwnedPrivateRegularFileWithoutSymlinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive.key")
	original := bytes.Repeat([]byte{9}, 32)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	value, err := ReadKeyFile(path)
	if err != nil || !bytes.Equal(value, original) {
		t.Fatal("private key could not be loaded", err)
	}
	clear(value)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(path); err == nil {
		t.Fatal("public key file accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "key-link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(link); err == nil {
		t.Fatal("key symlink accepted")
	}
	if err := os.WriteFile(path, []byte("short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadKeyFile(path); err == nil {
		t.Fatal("incorrect key length accepted")
	}
}
