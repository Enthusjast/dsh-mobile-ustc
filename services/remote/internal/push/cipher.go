package push

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"regexp"
)

// Keys come from a protected deployment file. Old IDs decrypt existing rows during rotation.
type Cipher struct {
	active string
	keys   map[string]cipher.AEAD
	lookup []byte
}

func (*Cipher) String() string   { return "PushCipher" }
func (*Cipher) GoString() string { return "PushCipher" }

var keyID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

func NewCipher(active string, keys map[string][]byte, lookup []byte) (*Cipher, error) {
	if !keyID.MatchString(active) || len(keys) < 1 || len(keys) > 8 || len(lookup) != 32 {
		return nil, ErrInvalid
	}
	result := &Cipher{active: active, keys: make(map[string]cipher.AEAD), lookup: append([]byte(nil), lookup...)}
	for id, key := range keys {
		if !keyID.MatchString(id) || len(key) != 32 {
			return nil, ErrInvalid
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, ErrInvalid
		}
		sealed, err := cipher.NewGCM(block)
		if err != nil {
			return nil, ErrInvalid
		}
		result.keys[id] = sealed
	}
	if result.keys[active] == nil {
		return nil, ErrInvalid
	}
	return result, nil
}
func (keys *Cipher) Seal(plain []byte, binding string) ([]byte, error) {
	if len(plain) < 1 || len(plain) > 8192 || len(binding) < 1 || len(binding) > 1024 {
		return nil, ErrInvalid
	}
	aead := keys.keys[keys.active]
	prefix := append([]byte{1, byte(len(keys.active))}, []byte(keys.active)...)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ErrCipher
	}
	aad := append(append([]byte(nil), prefix...), []byte("\x00dsh-push-v1\x00"+binding)...)
	return aead.Seal(append(prefix, nonce...), nonce, plain, aad), nil
}
func (keys *Cipher) Open(body []byte, binding string) ([]byte, error) {
	if len(body) < 2 || len(body) > 8300 || body[0] != 1 {
		return nil, ErrCipher
	}
	end := 2 + int(body[1])
	if end > len(body) {
		return nil, ErrCipher
	}
	aead := keys.keys[string(body[2:end])]
	if aead == nil || len(body) < end+aead.NonceSize()+aead.Overhead() {
		return nil, ErrCipher
	}
	aad := append(append([]byte(nil), body[:end]...), []byte("\x00dsh-push-v1\x00"+binding)...)
	plain, err := aead.Open(nil, body[end:end+aead.NonceSize()], body[end+aead.NonceSize():], aad)
	if err != nil || len(plain) < 1 || len(plain) > 8192 {
		clear(plain)
		return nil, ErrCipher
	}
	return plain, nil
}
func (keys *Cipher) AddressHash(provider, project, address string) string {
	hash := hmac.New(sha256.New, keys.lookup)
	_, _ = hash.Write([]byte("dsh-push-address-v1\x00" + provider + "\x00" + project + "\x00" + address))
	return hex.EncodeToString(hash.Sum(nil))
}
