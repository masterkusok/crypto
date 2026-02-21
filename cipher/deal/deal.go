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

type KeyScheduler struct{}

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

type DESAdapter struct {
	des cipher.BlockCipher
}

func NewDESAdapter() *DESAdapter {
	return &DESAdapter{des: des.NewDES()}
}

func (a *DESAdapter) Transform(ctx context.Context, block, roundKey []byte) ([]byte, error) {
	if len(block) != 8 {
		return nil, errors.ErrInvalidBlockSize
	}

	if err := a.des.SetKey(ctx, roundKey); err != nil {
		return nil, errors.Annotate(err, "failed to set DES key: %w")
	}

	return a.des.Encrypt(ctx, block)
}

type DEAL struct {
	*cipher.FeistelNetwork
}

func NewDEAL() *DEAL {
	return &DEAL{
		FeistelNetwork: cipher.NewFeistelNetwork(&KeyScheduler{}, NewDESAdapter(), dealBlockSize),
	}
}
