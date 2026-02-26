package tripledes

import (
	"context"

	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/cipher/des"
	"github.com/masterkusok/crypto/errors"
)

const (
	tripledesBlockSize = 8
	tripledesKeySize2  = 16
	tripledesKeySize3  = 24
)

type TripleDES struct {
	des1, des2, des3 cipher.BlockCipher
	key              []byte
}

func NewTripleDES() *TripleDES {
	return &TripleDES{
		des1: des.NewDES(),
		des2: des.NewDES(),
		des3: des.NewDES(),
	}
}

func (t *TripleDES) SetKey(ctx context.Context, key []byte) error {
	if len(key) != tripledesKeySize2 && len(key) != tripledesKeySize3 {
		return errors.ErrInvalidKeySize
	}

	t.key = make([]byte, len(key))
	copy(t.key, key)

	k1 := key[:8]
	k2 := key[8:16]
	var k3 []byte
	if len(key) == tripledesKeySize3 {
		k3 = key[16:24]
	} else {
		k3 = k1
	}

	if err := t.des1.SetKey(ctx, k1); err != nil {
		return errors.Annotate(err, "failed to set K1: %w")
	}
	if err := t.des2.SetKey(ctx, k2); err != nil {
		return errors.Annotate(err, "failed to set K2: %w")
	}
	if err := t.des3.SetKey(ctx, k3); err != nil {
		return errors.Annotate(err, "failed to set K3: %w")
	}

	return nil
}

func (t *TripleDES) Encrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != tripledesBlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	temp, err := t.des3.Encrypt(ctx, block)
	if err != nil {
		return nil, errors.Annotate(err, "first encryption failed: %w")
	}

	temp, err = t.des2.Decrypt(ctx, temp)
	if err != nil {
		return nil, errors.Annotate(err, "decryption failed: %w")
	}

	return t.des1.Encrypt(ctx, temp)
}

func (t *TripleDES) Decrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != tripledesBlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	temp, err := t.des1.Decrypt(ctx, block)
	if err != nil {
		return nil, errors.Annotate(err, "first decryption failed: %w")
	}

	temp, err = t.des2.Encrypt(ctx, temp)
	if err != nil {
		return nil, errors.Annotate(err, "encryption failed: %w")
	}

	return t.des3.Decrypt(ctx, temp)
}

func (t *TripleDES) BlockSize() int {
	return tripledesBlockSize
}
