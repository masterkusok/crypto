package cipher

import "context"

type KeyScheduler interface {
	GenerateRoundKeys(ctx context.Context, key []byte) ([][]byte, error)
}

type RoundFunction interface {
	Transform(ctx context.Context, block, roundKey []byte) ([]byte, error)
}

type BlockCipher interface {
	SetKey(ctx context.Context, key []byte) error
	Encrypt(ctx context.Context, block []byte) ([]byte, error)
	Decrypt(ctx context.Context, block []byte) ([]byte, error)
	BlockSize() int
}
