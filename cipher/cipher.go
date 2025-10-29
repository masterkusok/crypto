// Package cipher contains all utilities for encrypting/decrypting data.
package cipher

// KeyExpander is and interface for entities that implement key expanding logic
// (round keys generation).
type KeyExpander interface {
	ExpandKey(key []byte) [][]byte
}

// BlockCipher is an interface for entities that implement block encryption
// logic.
type BlockCipher interface {
	EncryptBlock(block []byte, roundKey []byte) []byte
	DecryptBlock(block []byte, roundKey []byte) []byte
}

// SymmetricAlgorithm is an interface for symmetric cipher algorithms.
type SymmetricAlgorithm interface {
	// SetEncryptionKey sets key, that will be used during text encryption.
	SetEncryptionKey(key []byte)

	// SetDecryptionKey sets key, that will be used during text decryption.
	SetDecryptionKey(key []byte)

	// Encrypt encrypts block using encryption key.
	Encrypt(block []byte) []byte

	// Decrypt decrypts block using decryption key.
	Decrypt(block []byte) []byte
}
