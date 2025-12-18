package cipher_test

import (
	"context"
	"testing"

	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/cipher/des"
)

func TestCipherContextModes(t *testing.T) {
	ctx := context.Background()
	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	iv := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	plaintext := []byte("Test message for encryption!")

	modes := []cipher.Mode{cipher.ECB, cipher.CBC, cipher.PCBC, cipher.CFB, cipher.OFB, cipher.CTR, cipher.RandomDelta}
	modeNames := []string{"ECB", "CBC", "PCBC", "CFB", "OFB", "CTR", "RandomDelta"}

	for i, mode := range modes {
		t.Run(modeNames[i], func(t *testing.T) {
			cipherCtx, err := cipher.NewCipherContext(des.NewDES(), key, mode, cipher.PKCS7, iv)
			if err != nil {
				t.Fatalf("Failed to create cipher context: %v", err)
			}

			encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if string(plaintext) != string(decrypted) {
				t.Errorf("Decrypted text doesn't match original.\nExpected: %s\nGot: %s", plaintext, decrypted)
			}
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
			if err != nil {
				t.Fatalf("Padding failed: %v", err)
			}

			if len(padded)%blockSize != 0 {
				t.Errorf("Padded data length %d is not multiple of block size %d", len(padded), blockSize)
			}

			unpadded, err := cipher.Unpad(padded, scheme)
			if err != nil {
				t.Fatalf("Unpadding failed: %v", err)
			}

			if string(data) != string(unpadded) {
				t.Errorf("Unpadded data doesn't match original.\nExpected: %s\nGot: %s", data, unpadded)
			}
		})
	}
}
