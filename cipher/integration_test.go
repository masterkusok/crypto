package cipher_test

import (
	"context"
	"testing"

	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/cipher/des"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCipherContextModes(t *testing.T) {
	ctx := context.Background()
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	plaintext := []byte("Test message for encryption!")

	modes := []cipher.CipherMode{
		&cipher.ECBMode{},
		&cipher.CBCMode{},
		&cipher.PCBCMode{},
		&cipher.CFBMode{},
		&cipher.OFBMode{},
		&cipher.CTRMode{},
		&cipher.RandomDeltaMode{},
	}
	modeNames := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"}

	for i, mode := range modes {
		t.Run(modeNames[i], func(t *testing.T) {
			cipherCtx, err := cipher.NewCipherContext(des.NewDES(), key, mode, cipher.PKCS7, iv)
			require.NoError(t, err)

			encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
			require.NoError(t, err)

			decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
			require.NoError(t, err)

			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestPaddingSchemes(t *testing.T) {
	blockSize := 8
	data := []byte("Hello")

	schemes := []cipher.PaddingScheme{cipher.Zeros, cipher.ANSIX923, cipher.PKCS7}
	schemeNames := []string{"Zeros", "ANSIX923", "PKCS7"}

	for i, scheme := range schemes {
		t.Run(schemeNames[i], func(t *testing.T) {
			padded, err := cipher.Pad(data, blockSize, scheme)
			require.NoError(t, err)

			assert.Zero(t, len(padded)%blockSize)

			unpadded, err := cipher.Unpad(padded, scheme)
			require.NoError(t, err)

			assert.Equal(t, data, unpadded)
		})
	}
}
