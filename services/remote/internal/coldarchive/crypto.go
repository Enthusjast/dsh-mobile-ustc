package coldarchive

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"io"
	"sync"
)

const magic = "DSHCA001"
const HeaderSize = 8 + 32 + 12 + 8
const MaxArtifact = HeaderSize + MaxPlaintext + 16

type Key struct {
	mu     sync.RWMutex
	id     string
	value  [32]byte
	closed bool
}

func NewKey(id string, raw []byte) (*Key, error) {
	if !KeyID(id) || len(raw) != 32 {
		return nil, ErrInvalid
	}
	key := &Key{id: id}
	copy(key.value[:], raw)
	return key, nil
}
func (*Key) String() string   { return "coldarchive.Key" }
func (*Key) GoString() string { return "coldarchive.Key" }
func (key *Key) ID() string   { return key.id }
func (key *Key) Close()       { key.mu.Lock(); defer key.mu.Unlock(); clear(key.value[:]); key.closed = true }
func (key *Key) secret() ([32]byte, error) {
	key.mu.RLock()
	defer key.mu.RUnlock()
	if key.closed {
		return [32]byte{}, ErrUnavailable
	}
	return key.value, nil
}

func keyed(key *Key, domain string, parts ...[]byte) ([32]byte, error) {
	value, err := key.secret()
	if err != nil {
		return [32]byte{}, err
	}
	defer clear(value[:])
	mac := hmac.New(sha256.New, value[:])
	_, _ = io.WriteString(mac, domain)
	_, _ = mac.Write([]byte{0})
	for _, part := range parts {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(part)))
		_, _ = mac.Write(size[:])
		_, _ = mac.Write(part)
	}
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result, nil
}
func (key *Key) Fingerprint() (string, error) {
	value, err := keyed(key, "dsh-control-archive/key-fingerprint/v1", []byte(key.id))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}
func Digest(value []byte) string {
	result := sha256.Sum256(value)
	return hex.EncodeToString(result[:])
}
func EqualDigest(a, b string) bool {
	return len(a) == 64 && len(b) == 64 && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func Material() ([32]byte, [12]byte, error) {
	var salt [32]byte
	var nonce [12]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return salt, nonce, ErrUnavailable
	}
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return salt, nonce, ErrUnavailable
	}
	return salt, nonce, nil
}

func aead(key *Key, salt []byte) (cipher.AEAD, error) {
	derived, err := keyed(key, "dsh-control-archive/aes-256-gcm/v1", []byte(key.id), salt)
	if err != nil {
		return nil, err
	}
	defer clear(derived[:])
	block, err := aes.NewCipher(derived[:])
	if err != nil {
		return nil, ErrUnavailable
	}
	value, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrUnavailable
	}
	return value, nil
}

// Seal uses a random per-export subkey salt. Reuse of this material is valid
// only for exactly the same plaintext; callers must persist/check its hash.
func Seal(key *Key, payload Payload, salt [32]byte, nonce [12]byte) ([]byte, string, error) {
	if key == nil || payload.KeyID != key.id {
		return nil, "", ErrInvalid
	}
	plain, err := Encode(payload)
	if err != nil {
		return nil, "", err
	}
	defer clear(plain)
	result, err := SealEncoded(key, plain, salt, nonce)
	if err != nil {
		return nil, "", err
	}
	return result, Digest(plain), nil
}

// SealEncoded accepts previously validated bytes, allowing a retry to check
// their persisted hash before any reuse of a salt/nonce pair.
func SealEncoded(key *Key, plain []byte, salt [32]byte, nonce [12]byte) ([]byte, error) {
	if key == nil || len(plain) == 0 || len(plain) > MaxPlaintext {
		return nil, ErrInvalid
	}
	value, err := aead(key, salt[:])
	if err != nil {
		return nil, err
	}
	header := make([]byte, HeaderSize)
	copy(header, magic)
	copy(header[8:40], salt[:])
	copy(header[40:52], nonce[:])
	binary.BigEndian.PutUint64(header[52:60], uint64(len(plain)+value.Overhead()))
	ciphertext := value.Seal(nil, nonce[:], plain, header)
	result := append(header, ciphertext...)
	return result, nil
}

// OpenEncoded authenticates the container only. The caller must validate the
// decoded format, key ID, domain and export identity before using its content.
// The returned plaintext is owned by the caller and should be cleared.
func OpenEncoded(key *Key, artifact []byte) ([]byte, error) {
	if key == nil || len(artifact) < HeaderSize+16 || len(artifact) > MaxArtifact || string(artifact[:8]) != magic {
		return nil, ErrInvalid
	}
	length := binary.BigEndian.Uint64(artifact[52:60])
	if length < 16 || length > MaxPlaintext+16 || length != uint64(len(artifact)-HeaderSize) {
		return nil, ErrInvalid
	}
	value, err := aead(key, artifact[8:40])
	if err != nil {
		return nil, err
	}
	plain, err := value.Open(nil, artifact[40:52], artifact[HeaderSize:], artifact[:HeaderSize])
	if err != nil {
		return nil, ErrInvalid
	}
	return plain, nil
}

func Open(key *Key, artifact []byte, domainID, exportID string) (Payload, error) {
	if key == nil || !UUID(domainID) || !UUID(exportID) {
		return Payload{}, ErrInvalid
	}
	plain, err := OpenEncoded(key, artifact)
	if err != nil {
		return Payload{}, err
	}
	defer clear(plain)
	payload, err := Decode(plain)
	if err != nil || payload.KeyID != key.id || payload.DomainID != domainID || payload.ExportID != exportID {
		return Payload{}, ErrInvalid
	}
	return payload, nil
}
