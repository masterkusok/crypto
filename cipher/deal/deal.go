// Package deal implements the DEAL encryption algorithm.
package deal

import (
	"context"

	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/cipher/des"
	"github.com/masterkusok/crypto/errors"
)

const (
	dealBlockSize = 16
	dealKeySize   = 24
	dealRounds    = 6
)

// KeyScheduler implements DEAL key scheduling.
type KeyScheduler struct{}

// GenerateRoundKeys generates round keys for DEAL.
func (k *KeyScheduler) GenerateRoundKeys(ctx context.Context, key []byte) ([][]byte, error) {
	if len(key) != dealKeySize {
		return nil, errors.ErrInvalidKeySize
	}

	roundKeys := make([][]byte, dealRounds)
	for i := 0; i < dealRounds; i++ {
		roundKeys[i] = make([]byte, 8)
		copy(roundKeys[i], key[i%3*8:(i%3+1)*8])
	}

	return roundKeys, nil
}

// DESAdapter adapts DES to be used as DEAL round function.
type DESAdapter struct {
	des cipher.BlockCipher
}

// NewDESAdapter creates a DES adapter for DEAL.
func NewDESAdapter() *DESAdapter {
	return &DESAdapter{des: des.NewDES()}
}

// Transform applies DES encryption as the round function.
func (a *DESAdapter) Transform(ctx context.Context, block, roundKey []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.ErrInvalidBlockSize
	}

	if err := a.des.SetKey(ctx, roundKey); err != nil {
		return nil, errors.Annotate(err, "failed to set DES key: %w")
	}

	return a.des.Encrypt(ctx, block)
}

// DEAL implements the DEAL cipher.
type DEAL struct {
	*cipher.FeistelNetwork
}

// NewDEAL creates a new DEAL cipher.
func NewDEAL() *DEAL {
	return &DEAL{
		FeistelNetwork: cipher.NewFeistelNetwork(&KeyScheduler{}, NewDESAdapter(), dealBlockSize),
	}
}
