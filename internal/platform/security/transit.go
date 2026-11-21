package security

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"
)

var (
	ErrTransitDecryptionFailed = errors.New("transit decryption failed")
	ErrInvalidKeyVersion       = errors.New("invalid transit key version")
)

// TransitEncryptor defines the port interface for envelope encryption via a key vault or hardware security module.
type TransitEncryptor interface {
	Encrypt(ctx context.Context, plaintext []byte) (ciphertext []byte, keyVersion int, err error)
	Decrypt(ctx context.Context, ciphertext []byte, keyVersion int) (plaintext []byte, err error)
}

// AESGCMTransitEncryptor implements TransitEncryptor using authenticated AES-256-GCM with key versioning.
type AESGCMTransitEncryptor struct {
	mu             sync.RWMutex
	keys           map[int][]byte
	currentVersion int
}

// NewAESGCMTransitEncryptor creates a TransitEncryptor backed by a 32-byte key.
// If secret is less than 32 bytes, SHA-256 is used to derive a 256-bit key.
func NewAESGCMTransitEncryptor(secret string, keyVersion int) (*AESGCMTransitEncryptor, error) {
	if secret == "" {
		return nil, errors.New("transit encryption secret cannot be empty")
	}
	if keyVersion < 1 {
		keyVersion = 1
	}

	h := sha256.Sum256([]byte(secret))
	key := make([]byte, 32)
	copy(key, h[:])

	return &AESGCMTransitEncryptor{
		keys:           map[int][]byte{keyVersion: key},
		currentVersion: keyVersion,
	}, nil
}

// AddKeyVersion registers an additional key version to support decryption of previously encrypted secrets after key rotation.
func (t *AESGCMTransitEncryptor) AddKeyVersion(keyVersion int, secret string) error {
	if secret == "" {
		return errors.New("transit encryption secret cannot be empty")
	}
	if keyVersion < 1 {
		return errors.New("key version must be positive")
	}
	h := sha256.Sum256([]byte(secret))
	key := make([]byte, 32)
	copy(key, h[:])

	t.mu.Lock()
	defer t.mu.Unlock()

	existing, ok := t.keys[keyVersion]
	if ok {
		if !bytes.Equal(existing, key) {
			return fmt.Errorf("key version %d already registered with different secret", keyVersion)
		}
		return nil
	}

	t.keys[keyVersion] = key
	return nil
}

// Encrypt encrypts plaintext using AES-256-GCM and prepends the random 12-byte nonce.
func (t *AESGCMTransitEncryptor) Encrypt(ctx context.Context, plaintext []byte) ([]byte, int, error) {
	t.mu.RLock()
	key, ok := t.keys[t.currentVersion]
	version := t.currentVersion
	t.mu.RUnlock()

	if !ok {
		return nil, 0, ErrInvalidKeyVersion
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, 0, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, version, nil
}

// Decrypt decrypts an authenticated ciphertext using the corresponding key version.
func (t *AESGCMTransitEncryptor) Decrypt(ctx context.Context, ciphertext []byte, keyVersion int) ([]byte, error) {
	t.mu.RLock()
	key, ok := t.keys[keyVersion]
	t.mu.RUnlock()

	if !ok {
		return nil, ErrInvalidKeyVersion
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, ErrTransitDecryptionFailed
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrTransitDecryptionFailed
	}

	return plaintext, nil
}
