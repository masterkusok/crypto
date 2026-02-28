package rsa

import (
	"os"
	"testing"

	cryptoMath "github.com/masterkusok/crypto/math"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRSAKeyGeneration(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	require.NoError(t, rsa.GenerateKeyPair())

	assert.NotNil(t, rsa.GetPublicKey())
	assert.NotNil(t, rsa.GetPrivateKey())
}

func TestRSAEncryptDecrypt(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	require.NoError(t, rsa.GenerateKeyPair())

	message := []byte("Hello, RSA!")

	ciphertext, err := rsa.Encrypt(message)
	require.NoError(t, err)

	decrypted, err := rsa.Decrypt(ciphertext)
	require.NoError(t, err)

	assert.Equal(t, message, decrypted)
}

func TestRSAMultipleKeyGeneration(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	for i := 0; i < 3; i++ {
		require.NoError(t, rsa.GenerateKeyPair())

		message := []byte("Test message")
		ciphertext, err := rsa.Encrypt(message)
		require.NoError(t, err)

		decrypted, err := rsa.Decrypt(ciphertext)
		require.NoError(t, err)

		assert.Equal(t, message, decrypted)
	}
}

func TestRSADifferentTests(t *testing.T) {
	tests := []struct {
		name   string
		tester cryptoMath.PrimalityTester
	}{
		{"Fermat", cryptoMath.NewFermatTest()},
		{"SolovayStrassen", cryptoMath.NewSolovayStrassenTest()},
		{"MillerRabin", cryptoMath.NewMillerRabinTest()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rsa := NewRSA(tt.tester, 0.99, 512)
			require.NoError(t, rsa.GenerateKeyPair())

			message := []byte("Test")
			ciphertext, err := rsa.Encrypt(message)
			require.NoError(t, err)

			decrypted, err := rsa.Decrypt(ciphertext)
			require.NoError(t, err)

			assert.Equal(t, message, decrypted)
		})
	}
}

func TestRSANoKeyError(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	_, err := rsa.Encrypt([]byte("test"))
	require.Error(t, err)

	_, err = rsa.Decrypt([]byte("test"))
	require.Error(t, err)
}

func TestRSAEncryptFile(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	require.NoError(t, rsa.GenerateKeyPair())

	inputFile := t.TempDir() + "/input.txt"
	encryptedFile := t.TempDir() + "/encrypted.bin"

	originalData := []byte("RSA file encryption test!")
	require.NoError(t, os.WriteFile(inputFile, originalData, 0o644))

	require.NoError(t, rsa.EncryptFile(inputFile, encryptedFile))

	encryptedData, err := os.ReadFile(encryptedFile)
	require.NoError(t, err)
	assert.NotEqual(t, originalData, encryptedData)
}

func TestRSADecryptFile(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	require.NoError(t, rsa.GenerateKeyPair())

	inputFile := t.TempDir() + "/input.txt"
	encryptedFile := t.TempDir() + "/encrypted.bin"
	decryptedFile := t.TempDir() + "/decrypted.txt"

	originalData := []byte("RSA file encryption test!")
	require.NoError(t, os.WriteFile(inputFile, originalData, 0o644))

	require.NoError(t, rsa.EncryptFile(inputFile, encryptedFile))
	require.NoError(t, rsa.DecryptFile(encryptedFile, decryptedFile))

	decryptedData, err := os.ReadFile(decryptedFile)
	require.NoError(t, err)
	assert.Equal(t, originalData, decryptedData)
}
