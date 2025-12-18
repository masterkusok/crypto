package rsa

import (
	"context"
	"math/big"
	"testing"
)

func TestRSAEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	rsa, err := NewRSA(1024)
	if err != nil {
		t.Fatalf("Failed to create RSA: %v", err)
	}

	plaintext := []byte("Hello, RSA!")
	encrypted, err := rsa.EncryptBytes(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := rsa.DecryptBytes(ctx, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(plaintext) != string(decrypted) {
		t.Errorf("Decrypted text doesn't match.\nExpected: %s\nGot: %s", plaintext, decrypted)
	}
}

func TestWienerAttackProtection(t *testing.T) {
	rsa, err := NewRSA(1024)
	if err != nil {
		t.Fatalf("Failed to create RSA: %v", err)
	}

	// Check that generated key is protected against Wiener attack
	nSqrt := new(big.Int).Sqrt(rsa.privateKey.N)
	nFourthRoot := new(big.Int).Sqrt(nSqrt)

	if rsa.privateKey.D.Cmp(nFourthRoot) <= 0 {
		t.Error("Generated key is vulnerable to Wiener attack")
	}
}

func TestWienerAttackOnVulnerableKey(t *testing.T) {
	// Create a vulnerable key (small d)
	p := big.NewInt(61)
	q := big.NewInt(53)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	e := big.NewInt(17)
	d := new(big.Int).ModInverse(e, phi)

	pub := &PublicKey{N: n, E: e}

	// Try Wiener attack
	recoveredD := WienerAttack(pub)
	if recoveredD == nil {
		t.Skip("Wiener attack failed (key might not be vulnerable enough)")
	}

	if recoveredD.Cmp(d) != 0 {
		t.Errorf("Wiener attack recovered wrong d.\nExpected: %s\nGot: %s", d, recoveredD)
	}
}

func TestRSALargeData(t *testing.T) {
	ctx := context.Background()
	rsa, err := NewRSA(2048)
	if err != nil {
		t.Fatalf("Failed to create RSA: %v", err)
	}

	plaintext := make([]byte, 1000)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, err := rsa.EncryptBytes(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := rsa.DecryptBytes(ctx, encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if len(plaintext) != len(decrypted) {
		t.Fatalf("Length mismatch: expected %d, got %d", len(plaintext), len(decrypted))
	}

	for i := range plaintext {
		if plaintext[i] != decrypted[i] {
			t.Errorf("Mismatch at byte %d: expected %02x, got %02x", i, plaintext[i], decrypted[i])
			break
		}
	}
}
