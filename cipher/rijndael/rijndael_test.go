package rijndael

import (
	"bytes"
	"context"
	"testing"
)

func TestRijndael128(t *testing.T) {
	// Simple encrypt-decrypt test
	key := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	plaintext := []byte{
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
	}

	r, err := NewRijndael(16, 16, 0x1B) // AES polynomial
	if err != nil {
		t.Fatalf("Failed to create Rijndael: %v", err)
	}

	ctx := context.Background()
	err = r.SetKey(ctx, key)
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	ciphertext, err := r.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	t.Logf("Ciphertext: %x", ciphertext)

	decrypted, err := r.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch\nExpected: %x\nGot: %x", plaintext, decrypted)
	}
}

func TestRijndael192(t *testing.T) {
	key := make([]byte, 24)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, 24)
	for i := range plaintext {
		plaintext[i] = byte(i * 2)
	}

	r, err := NewRijndael(24, 24, 0x1B)
	if err != nil {
		t.Fatalf("Failed to create Rijndael: %v", err)
	}

	ctx := context.Background()
	err = r.SetKey(ctx, key)
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	ciphertext, err := r.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := r.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch")
	}
}

func TestRijndael256(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i * 3)
	}

	r, err := NewRijndael(32, 32, 0x1B)
	if err != nil {
		t.Fatalf("Failed to create Rijndael: %v", err)
	}

	ctx := context.Background()
	err = r.SetKey(ctx, key)
	if err != nil {
		t.Fatalf("Failed to set key: %v", err)
	}

	ciphertext, err := r.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := r.Decrypt(ctx, ciphertext)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("Decryption mismatch")
	}
}

func TestRijndaelDifferentModulus(t *testing.T) {
	// Test with different irreducible polynomial
	irr := []byte{0x1B, 0x1D}

	for _, mod := range irr {
		t.Run("Modulus_0x"+string(rune(mod)), func(t *testing.T) {
			key := make([]byte, 16)
			plaintext := []byte("Test message!!!!")

			r, err := NewRijndael(16, 16, mod)
			if err != nil {
				t.Fatalf("Failed to create Rijndael: %v", err)
			}

			ctx := context.Background()
			err = r.SetKey(ctx, key)
			if err != nil {
				t.Fatalf("Failed to set key: %v", err)
			}

			ciphertext, err := r.Encrypt(ctx, plaintext)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			decrypted, err := r.Decrypt(ctx, ciphertext)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("Decryption mismatch")
			}
		})
	}
}

func TestRijndaelInvalidSizes(t *testing.T) {
	_, err := NewRijndael(15, 16, 0x1B)
	if err == nil {
		t.Error("Expected error for invalid block size")
	}

	_, err = NewRijndael(16, 15, 0x1B)
	if err == nil {
		t.Error("Expected error for invalid key size")
	}
}

func TestRijndaelReducibleModulus(t *testing.T) {
	_, err := NewRijndael(16, 16, 0x02) // x is reducible
	if err == nil {
		t.Error("Expected error for reducible modulus")
	}
}

func TestRijndaelBlockSize(t *testing.T) {
	r, _ := NewRijndael(16, 16, 0x1B)
	if r.BlockSize() != 16 {
		t.Errorf("BlockSize() = %d, want 16", r.BlockSize())
	}
}
