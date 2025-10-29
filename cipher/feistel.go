package cipher

// FeistelNetworkConfig is configuration structure for [FeistelNetwork].
type FeistelNetworkConfig struct {
	// F is a feistel network function.
	F BlockCipher

	// Expander is used for generating round keys.
	Expander KeyExpander
}

// FeistelNetwork is implementation of Feistel Network functionality.
type FeistelNetwork struct {
	encryptionKey []byte
	decryptionKey []byte
	f             BlockCipher
	expander      KeyExpander
}

// type check
var _ (SymmetricAlgorithm) = (*FeistelNetwork)(nil)

// NewFeistelNetwork returns new FeistelNetwork object.  c must not be nil.
func NewFeistelNetwork(c *FeistelNetworkConfig) *FeistelNetwork {
	return &FeistelNetwork{
		f:        c.F,
		expander: c.Expander,
	}
}

func (f *FeistelNetwork) SetEncryptionKey(key []byte) {
	f.encryptionKey = make([]byte, len(key))
	copy(f.encryptionKey, key)
}

func (f *FeistelNetwork) SetDecryptionKey(key []byte) {
	f.decryptionKey = make([]byte, len(key))
	copy(f.decryptionKey, key)
}

func (f *FeistelNetwork) Encrypt(block []byte) []byte {
	if len(block)%2 != 0 {
		panic("block size must be even for Feistel network")
	}

	blockCopy := make([]byte, len(block))
	copy(blockCopy, block)

	L, R := blockCopy[0:len(blockCopy)/2], blockCopy[len(blockCopy)/2:]
	keys := f.expander.ExpandKey(f.encryptionKey)

	for _, key := range keys {
		Li := R
		Ri := xorBytes(L, f.f.EncryptBlock(R, key))

		L, R = Li, Ri
	}

	return append(R, L...)
}

func (f *FeistelNetwork) Decrypt(block []byte) []byte {
	if len(block)%2 != 0 {
		panic("block size must be even for Feistel network")
	}

	blockCopy := make([]byte, len(block))
	copy(blockCopy, block)

	L, R := blockCopy[0:len(blockCopy)/2], blockCopy[len(blockCopy)/2:]
	keys := f.expander.ExpandKey(f.decryptionKey)

	for i := len(keys) - 1; i >= 0; i-- {
		roundKey := keys[i]

		Ri := L
		Li := xorBytes(R, f.f.EncryptBlock(L, roundKey))

		L, R = Li, Ri
	}

	return append(L, R...)
}
