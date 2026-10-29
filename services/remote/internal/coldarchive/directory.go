package coldarchive

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

type Directory struct {
	root          *os.Root
	path          string
	device, inode uint64
	maxArtifact   int
}

// OpenDirectory anchors operations to an already-existing owner-only directory.
// The resolved path cannot contain symlinks; no caller-controlled file names are used.
func OpenDirectory(path string) (*Directory, error) {
	return OpenDirectoryWithLimit(path, MaxArtifact)
}

// OpenDirectoryWithLimit keeps the same protected publication semantics with
// an explicit file bound, never exceeding MaxExtendedArtifact.
func OpenDirectoryWithLimit(path string, limit int) (*Directory, error) {
	if limit < HeaderSize+16 || limit > MaxExtendedArtifact {
		return nil, ErrInvalid
	}
	if !filepath.IsAbs(path) || strings.IndexByte(path, 0) >= 0 || len(path) > 4096 {
		return nil, ErrInvalid
	}
	path = filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalid
	}
	device, inode, err := identity(before)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(before, actual) {
		_ = root.Close()
		return nil, ErrInvalid
	}
	return &Directory{root: root, path: path, device: device, inode: inode, maxArtifact: limit}, nil
}
func (*Directory) String() string         { return "coldarchive.Directory" }
func (*Directory) GoString() string       { return "coldarchive.Directory" }
func (directory *Directory) Close() error { return directory.root.Close() }
func (directory *Directory) Fingerprint(key *Key) (string, error) {
	var ids [16]byte
	binary.BigEndian.PutUint64(ids[:8], directory.device)
	binary.BigEndian.PutUint64(ids[8:], directory.inode)
	value, err := keyed(key, "dsh-control-archive/destination/v1", []byte(directory.path), ids[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
func filename(id string) (string, error) {
	if !UUID(id) {
		return "", ErrInvalid
	}
	return id + ".dshca", nil
}

func (directory *Directory) sync() error {
	file, err := directory.root.Open(".")
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (directory *Directory) read(name string) ([]byte, error) {
	before, err := directory.root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil, os.ErrNotExist
	}
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() < HeaderSize+16 || before.Size() > int64(directory.maxArtifact) {
		return nil, ErrInvalid
	}
	if _, _, err := identity(before); err != nil {
		return nil, err
	}
	file, err := directory.root.Open(name)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return nil, ErrInvalid
	}
	value, err := io.ReadAll(io.LimitReader(file, int64(directory.maxArtifact)+1))
	if err != nil || len(value) > directory.maxArtifact || int64(len(value)) != actual.Size() {
		clear(value)
		return nil, ErrInvalid
	}
	return value, nil
}

func (directory *Directory) Read(id string) ([]byte, error) {
	name, err := filename(id)
	if err != nil {
		return nil, err
	}
	return directory.read(name)
}

func (directory *Directory) syncFile(name string) error {
	before, err := directory.root.Lstat(name)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 {
		return ErrInvalid
	}
	if _, _, err := identity(before); err != nil {
		return err
	}
	file, err := directory.root.Open(name)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	actual, err := file.Stat()
	if err != nil || !os.SameFile(before, actual) {
		return ErrInvalid
	}
	if err := file.Sync(); err != nil {
		return ErrUnavailable
	}
	return nil
}

// Publish never overwrites an existing artifact. A matching file is reusable;
// every claimed success has been read back, validated and directory-synced.
func (directory *Directory) Publish(id string, artifact []byte, validate func([]byte) error) error {
	name, err := filename(id)
	if err != nil || len(artifact) > directory.maxArtifact || len(artifact) < HeaderSize+16 || validate == nil {
		return ErrInvalid
	}
	if validate(artifact) != nil {
		return ErrInvalid
	}
	check := func(name string) error {
		actual, err := directory.read(name)
		if err != nil {
			return err
		}
		defer clear(actual)
		if !EqualDigest(Digest(actual), Digest(artifact)) || validate(actual) != nil {
			return ErrConflict
		}
		return nil
	}
	if err := check(name); err == nil {
		if err := directory.syncFile(name); err != nil {
			return err
		}
		if err := check(name); err != nil {
			return err
		}
		return directory.sync()
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return ErrUnavailable
	}
	temporary := "." + id + "-" + hex.EncodeToString(random[:]) + ".tmp"
	file, err := directory.root.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrUnavailable
	}
	defer directory.root.Remove(temporary)
	if written, err := file.Write(artifact); err != nil || written != len(artifact) {
		_ = file.Close()
		return ErrUnavailable
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return ErrUnavailable
	}
	if err := check(temporary); err != nil {
		return err
	}
	if err := directory.root.Link(temporary, name); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return ErrUnavailable
		}
		if err := check(name); err != nil {
			return err
		}
		if err := directory.syncFile(name); err != nil {
			return err
		}
		if err := check(name); err != nil {
			return err
		}
	}
	if err := directory.sync(); err != nil {
		return err
	}
	if err := directory.root.Remove(temporary); err != nil {
		return ErrUnavailable
	}
	return directory.sync()
}
