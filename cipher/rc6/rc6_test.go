package rc6

import (
	"context"
	"testing"
)

func TestRC6EncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	rc6 := NewRC6()

	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	plaintext := []byte{
		0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
		0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
	}

	if err := rc6.SetKey(ctx, key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	encrypted, err := rc6.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := rc6.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("Mismatch at byte %d: expected %02x, got %02x", i, plaintext[i], decrypted[i])
		}
	}
}

func TestRC6DifferentKeySizes(t *testing.T) {
	ctx := context.Background()
	rc6 := NewRC6()

	keySizes := []int{16, 24, 32}
	plaintext := make([]byte, 16)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}

	for _, keySize := range keySizes {
		t.Run(string(rune(keySize)), func(t *testing.T) {
			key := make([]byte, keySize)
			for i := range key {
				key[i] = byte(i)
			}

			if err := rc6.SetKey(ctx, key); err != nil {
				t.Fatalf("SetKey failed for key size %d: %v", keySize, err)
			}

			encrypted, err := rc6.Encrypt(ctx, plaintext)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			decrypted, err := rc6.Decrypt(ctx, encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			for i := range plaintext {
				if plaintext[i] != decrypted[i] {
					t.Errorf("Mismatch at byte %d: expected %02x, got %02x", i, plaintext[i], decrypted[i])
					break
				}
			}
		})
	}
}

func TestRC6InvalidBlockSize(t *testing.T) {
	ctx := context.Background()
	rc6 := NewRC6()

	key := make([]byte, 16)
	rc6.SetKey(ctx, key)

	invalidBlock := []byte{0x01, 0x02, 0x03}
	_, err := rc6.Encrypt(ctx, invalidBlock)
	if err == nil {
		t.Error("Expected error for invalid block size, got nil")
	}
}
