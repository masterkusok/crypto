package cipher

import (
	"context"

	"github.com/masterkusok/crypto/errors"
)

type FeistelNetwork struct {
	keyScheduler  KeyScheduler
	RoundFunction RoundFunction
	RoundKeys     [][]byte
	blockSize     int
}

func NewFeistelNetwork(keyScheduler KeyScheduler, roundFunction RoundFunction, blockSize int) *FeistelNetwork {
	return &FeistelNetwork{
		keyScheduler:  keyScheduler,
		RoundFunction: roundFunction,
		blockSize:     blockSize,
	}
}

func (f *FeistelNetwork) SetKey(ctx context.Context, key []byte) error {
	roundKeys, err := f.keyScheduler.GenerateRoundKeys(ctx, key)
	if err != nil {
		return errors.Annotate(err, "failed to generate round keys: %w")
	}

	f.RoundKeys = roundKeys

	return nil
}

func (f *FeistelNetwork) Encrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != f.blockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	halfSize := f.blockSize / 2
	left := make([]byte, halfSize)
	right := make([]byte, halfSize)
	copy(left, block[:halfSize])
	copy(right, block[halfSize:])

	for _, roundKey := range f.RoundKeys {
		transformed, err := f.RoundFunction.Transform(ctx, right, roundKey)
		if err != nil {
			return nil, errors.Annotate(err, "round function failed: %w")
		}

		newRight := xor(left, transformed)
		left = right
		right = newRight
	}

	result := make([]byte, f.blockSize)
	copy(result[:halfSize], left)
	copy(result[halfSize:], right)
	return result, nil
}

func (f *FeistelNetwork) Decrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != f.blockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	halfSize := f.blockSize / 2
	left := make([]byte, halfSize)
	right := make([]byte, halfSize)
	copy(left, block[:halfSize])
	copy(right, block[halfSize:])

	for i := len(f.RoundKeys) - 1; i >= 0; i-- {
		transformed, err := f.RoundFunction.Transform(ctx, left, f.RoundKeys[i])
		if err != nil {
			return nil, errors.Annotate(err, "round function failed: %w")
		}

		newLeft := xor(right, transformed)
		right = left
		left = newLeft
	}

	result := make([]byte, f.blockSize)
	copy(result[:halfSize], left)
	copy(result[halfSize:], right)
	return result, nil
}

func (f *FeistelNetwork) BlockSize() int {
	return f.blockSize
}

func xor(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
