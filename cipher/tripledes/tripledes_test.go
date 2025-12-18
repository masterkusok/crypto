package tripledes

import (
	"context"
	"testing"
)

func TestTripleDESEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	tripledes := NewTripleDES()

	// 24-byte key (3 * 8 bytes)
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
	}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	if err := tripledes.SetKey(ctx, key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	encrypted, err := tripledes.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decrypted, err := tripledes.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("Mismatch at byte %d: expected %02x, got %02x", i, plaintext[i], decrypted[i])
		}
	}
}

func TestTripleDESInvalidKeySize(t *testing.T) {
	ctx := context.Background()
	tripledes := NewTripleDES()

	invalidKey := []byte{0x01, 0x02, 0x03}
	err := tripledes.SetKey(ctx, invalidKey)
	if err == nil {
		t.Error("Expected error for invalid key size, got nil")
	}
}

func TestTripleDESInvalidBlockSize(t *testing.T) {
	ctx := context.Background()
	tripledes := NewTripleDES()

	key := make([]byte, 24)
	if err := tripledes.SetKey(ctx, key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	invalidBlock := []byte{0x01, 0x02, 0x03}
	_, err := tripledes.Encrypt(ctx, invalidBlock)
	if err == nil {
		t.Error("Expected error for invalid block size, got nil")
	}
}
