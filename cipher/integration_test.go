package cipher_test

import (
	"context"
	"os"
	"testing"

	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/cipher/deal"
	"github.com/masterkusok/crypto/cipher/des"
	"github.com/masterkusok/crypto/cipher/rijndael"
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

			resultChan, errChan := cipherCtx.EncryptBytes(ctx, plaintext)
			var encrypted []byte
			select {
			case encrypted = <-resultChan:
			case err := <-errChan:
				require.NoError(t, err)
			}

			resultChan, errChan = cipherCtx.DecryptBytes(ctx, encrypted)
			var decrypted []byte
			select {
			case decrypted = <-resultChan:
			case err := <-errChan:
				require.NoError(t, err)
			}

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

func TestFileEncryption(t *testing.T) {
	ctx := context.Background()
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	tests := []struct {
		name   string
		cipher cipher.BlockCipher
		key    []byte
	}{
		{
			name:   "DES",
			cipher: des.NewDES(),
			key:    []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1},
		},
		{
			name:   "DEAL",
			cipher: deal.NewDEAL(),
			key:    []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		},
		{
			name: "Rijndael-128",
			cipher: func() cipher.BlockCipher {
				r, _ := rijndael.NewRijndael(16, 16, 0x1B)
				return r
			}(),
			key: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputFile := t.TempDir() + "/input.txt"
			encryptedFile := t.TempDir() + "/encrypted.bin"
			decryptedFile := t.TempDir() + "/decrypted.txt"

			originalData := []byte("Test file encryption with multiple algorithms!")
			require.NoError(t, os.WriteFile(inputFile, originalData, 0644))

			cipherCtx, err := cipher.NewCipherContext(tt.cipher, tt.key, &cipher.CBCMode{}, cipher.PKCS7, iv[:tt.cipher.BlockSize()])
			require.NoError(t, err)

			err = cipherCtx.EncryptFile(ctx, inputFile, encryptedFile)
			require.NoError(t, err)

			err = cipherCtx.DecryptFile(ctx, encryptedFile, decryptedFile)
			require.NoError(t, err)

			decryptedData, err := os.ReadFile(decryptedFile)
			require.NoError(t, err)
			assert.Equal(t, originalData, decryptedData)
		})
	}
}
