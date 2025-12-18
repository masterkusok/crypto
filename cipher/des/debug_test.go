package des

import (
	"context"
	"fmt"
	"testing"
)

func TestDESDebug(t *testing.T) {
	ctx := context.Background()
	des := NewDES()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	if err := des.SetKey(ctx, key); err != nil {
		t.Fatalf("SetKey failed: %v", err)
	}

	fmt.Printf("Plaintext: %x\n", plaintext)

	encrypted, err := des.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Printf("Encrypted: %x\n", encrypted)

	decrypted, err := des.Decrypt(ctx, encrypted)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Printf("Decrypted: %x\n", decrypted)

	encrypted2, err := des.Encrypt(ctx, decrypted)
	if err != nil {
		t.Fatalf("Encrypt2 failed: %v", err)
	}
	fmt.Printf("Encrypted2: %x\n", encrypted2)
}
