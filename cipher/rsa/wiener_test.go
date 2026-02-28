package rsa

import (
	"math/big"
	"testing"

	cryptoMath "github.com/masterkusok/crypto/math"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

	require.True(t, result.Success)
	assert.Equal(t, 0, result.D.Cmp(d))
	assert.Equal(t, 0, result.Phi.Cmp(phi))
	assert.NotEmpty(t, result.Convergents)
}

func TestWienerAttackNotVulnerable(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	require.NoError(t, rsa.GenerateKeyPair())

	result := WienerAttack(rsa.GetPublicKey())

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Convergents)
}

func TestIsVulnerableToWiener(t *testing.T) {
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

	assert.True(t, IsVulnerableToWiener(pub))

	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	require.NoError(t, rsa.GenerateKeyPair())

	assert.False(t, IsVulnerableToWiener(rsa.GetPublicKey()))
}

func TestConvergents(t *testing.T) {
	e := big.NewInt(17)
	n := big.NewInt(3233)

	convergents := continuedFraction(e, n)

	assert.NotEmpty(t, convergents)

	for i, conv := range convergents {
		assert.NotNil(t, conv.Numerator, "Convergent %d numerator", i)
		assert.NotNil(t, conv.Denominator, "Convergent %d denominator", i)
	}
}
