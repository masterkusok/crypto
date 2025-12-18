// Package tripledes implements the Triple DES (3DES) encryption algorithm.
package tripledes

import (
	"context"

	"github.com/masterkusok/crypto/cipher/des"
	"github.com/masterkusok/crypto/errors"
)

const (
	tripledesBlockSize = 8
	tripledesKeySize   = 24 // 3 * 8 bytes
)

// TripleDES implements the 3DES cipher using EDE (Encrypt-Decrypt-Encrypt) mode.
type TripleDES struct {
	des1 *des.DES
	des2 *des.DES
	des3 *des.DES
}

// NewTripleDES creates a new TripleDES cipher.
func NewTripleDES() *TripleDES {
	return &TripleDES{
		des1: des.NewDES(),
		des2: des.NewDES(),
		des3: des.NewDES(),
	}
}

// SetKey configures the cipher with a 24-byte key (3 DES keys).
func (t *TripleDES) SetKey(ctx context.Context, key []byte) error {
	if len(key) != tripledesKeySize {
		return errors.ErrInvalidKeySize
	}

	// Split key into three 8-byte keys
	key1 := key[0:8]
	key2 := key[8:16]
	key3 := key[16:24]

	if err := t.des1.SetKey(ctx, key1); err != nil {
		return errors.Annotate(err, "failed to set DES1 key: %w")
	}

	if err := t.des2.SetKey(ctx, key2); err != nil {
		return errors.Annotate(err, "failed to set DES2 key: %w")
	}

	if err := t.des3.SetKey(ctx, key3); err != nil {
		return errors.Annotate(err, "failed to set DES3 key: %w")
	}

	return nil
}

// Encrypt encrypts a block using EDE (Encrypt-Decrypt-Encrypt) mode.
func (t *TripleDES) Encrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != tripledesBlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	// Encrypt with key1
	encrypted1, err := t.des1.Encrypt(ctx, block)
	if err != nil {
		return nil, errors.Annotate(err, "DES1 encryption failed: %w")
	}

	// Decrypt with key2
	decrypted, err := t.des2.Decrypt(ctx, encrypted1)
	if err != nil {
		return nil, errors.Annotate(err, "DES2 decryption failed: %w")
	}

	// Encrypt with key3
	encrypted2, err := t.des3.Encrypt(ctx, decrypted)
	if err != nil {
		return nil, errors.Annotate(err, "DES3 encryption failed: %w")
	}

	return encrypted2, nil
}

// Decrypt decrypts a block using EDE (Encrypt-Decrypt-Encrypt) mode in reverse.
func (t *TripleDES) Decrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != tripledesBlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	// Decrypt with key3
	decrypted1, err := t.des3.Decrypt(ctx, block)
	if err != nil {
		return nil, errors.Annotate(err, "DES3 decryption failed: %w")
	}

	// Encrypt with key2
	encrypted, err := t.des2.Encrypt(ctx, decrypted1)
	if err != nil {
		return nil, errors.Annotate(err, "DES2 encryption failed: %w")
	}

	// Decrypt with key1
	decrypted2, err := t.des1.Decrypt(ctx, encrypted)
	if err != nil {
		return nil, errors.Annotate(err, "DES1 decryption failed: %w")
	}

	return decrypted2, nil
}

// BlockSize returns the block size in bytes.
func (t *TripleDES) BlockSize() int {
	return tripledesBlockSize
}
