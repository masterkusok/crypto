package rsa

import (
	"bytes"
	"testing"

	cryptoMath "github.com/masterkusok/crypto/math"
)

func TestRSAKeyGeneration(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	err := rsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	if rsa.GetPublicKey() == nil {
		t.Error("Public key is nil")
	}
	if rsa.GetPrivateKey() == nil {
		t.Error("Private key is nil")
	}
}

func TestRSAEncryptDecrypt(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	err := rsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	message := []byte("Hello, RSA!")

	ciphertext, err := rsa.Encrypt(message)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := rsa.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("Decrypted message doesn't match original.\nExpected: %s\nGot: %s", message, decrypted)
	}
}

func TestRSAMultipleKeyGeneration(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	for i := 0; i < 3; i++ {
		err := rsa.GenerateKeyPair()
		if err != nil {
			t.Fatalf("Failed to generate key pair %d: %v", i+1, err)
		}

		message := []byte("Test message")
		ciphertext, err := rsa.Encrypt(message)
		if err != nil {
			t.Fatalf("Encryption failed on iteration %d: %v", i+1, err)
		}

		decrypted, err := rsa.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decryption failed on iteration %d: %v", i+1, err)
		}

		if !bytes.Equal(message, decrypted) {
			t.Errorf("Iteration %d: decrypted message doesn't match", i+1)
		}
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
			err := rsa.GenerateKeyPair()
			if err != nil {
				t.Fatalf("Failed to generate key pair with %s: %v", tt.name, err)
			}

			message := []byte("Test")
			ciphertext, err := rsa.Encrypt(message)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := rsa.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(message, decrypted) {
				t.Error("Decrypted message doesn't match")
			}
		})
	}
}

func TestRSANoKeyError(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)

	_, err := rsa.Encrypt([]byte("test"))
	if err == nil {
		t.Error("Expected error when encrypting without key")
	}

	_, err = rsa.Decrypt([]byte("test"))
	if err == nil {
		t.Error("Expected error when decrypting without key")
	}
}
