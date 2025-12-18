package cipher

import "context"

// KeyScheduler generates round keys from the main key.
type KeyScheduler interface {
	// GenerateRoundKeys generates round keys from the input key.
	GenerateRoundKeys(ctx context.Context, key []byte) ([][]byte, error)
}

// RoundFunction performs a single round transformation.
type RoundFunction interface {
	// Transform applies the round function to the input block with the round key.
	Transform(ctx context.Context, block, roundKey []byte) ([]byte, error)
}

// BlockCipher provides encryption and decryption operations.
type BlockCipher interface {
	// SetKey configures the cipher with round keys derived from the main key.
	SetKey(ctx context.Context, key []byte) error
	// Encrypt encrypts a single block.
	Encrypt(ctx context.Context, block []byte) ([]byte, error)
	// Decrypt decrypts a single block.
	Decrypt(ctx context.Context, block []byte) ([]byte, error)
	// BlockSize returns the block size in bytes.
	BlockSize() int
}
