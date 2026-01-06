package rsa

import (
	"math/big"
	"testing"

	cryptoMath "github.com/masterkusok/crypto/math"
)

func TestWienerAttackVulnerable(t *testing.T) {
	// Create vulnerable RSA key
	p := big.NewInt(10007)
	q := big.NewInt(10009)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	// Choose very small d (vulnerable to Wiener)
	d := big.NewInt(17)
	e := new(big.Int).ModInverse(d, phi)

	t.Logf("N = %v", n)
	t.Logf("e = %v", e)
	t.Logf("d = %v", d)
	t.Logf("phi = %v", phi)

	pub := &PublicKey{N: n, E: e}

	result := WienerAttack(pub)

	t.Logf("Convergents count: %d", len(result.Convergents))
	if result.Success {
		t.Logf("Found d = %v", result.D)
		t.Logf("Found phi = %v", result.Phi)
	}

	if !result.Success {
		t.Fatal("Attack should succeed on vulnerable key")
	}

	if result.D.Cmp(d) != 0 {
		t.Errorf("Found d = %v, expected %v", result.D, d)
	}

	if result.Phi.Cmp(phi) != 0 {
		t.Errorf("Found φ = %v, expected %v", result.Phi, phi)
	}

	if len(result.Convergents) == 0 {
		t.Error("No convergents computed")
	}
}

func TestWienerAttackNotVulnerable(t *testing.T) {
	// Create RSA with large d (not vulnerable)
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	err := rsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	result := WienerAttack(rsa.GetPublicKey())

	// Should not succeed because d is large
	if result.Success {
		t.Error("Attack should not succeed on secure key")
	}

	if len(result.Convergents) == 0 {
		t.Error("No convergents computed")
	}
}

func TestIsVulnerableToWiener(t *testing.T) {
	// Vulnerable key
	p := big.NewInt(10007)
	q := big.NewInt(10009)
	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)
	d := big.NewInt(17)
	e := new(big.Int).ModInverse(d, phi)

	pub := &PublicKey{N: n, E: e}

	if !IsVulnerableToWiener(pub) {
		t.Error("Key should be vulnerable to Wiener attack")
	}

	// Secure key
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	err := rsa.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if IsVulnerableToWiener(rsa.GetPublicKey()) {
		t.Error("Secure key should not be vulnerable to Wiener attack")
	}
}

func TestConvergents(t *testing.T) {
	e := big.NewInt(17)
	n := big.NewInt(3233)

	convergents := continuedFraction(e, n)

	if len(convergents) == 0 {
		t.Error("No convergents computed")
	}

	// Verify convergents are computed
	for i, conv := range convergents {
		if conv.Numerator == nil || conv.Denominator == nil {
			t.Errorf("Convergent %d has nil values", i)
		}
	}
}
