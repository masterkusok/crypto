package math

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGF256Add(t *testing.T) {
	tests := []struct {
		a, b, want byte
	}{
		{0x57, 0x83, 0xD4},
		{0xFF, 0xFF, 0x00},
		{0x00, 0x57, 0x57},
	}

	for _, tt := range tests {
		got := GF256Add(tt.a, tt.b)
		assert.Equal(t, tt.want, got, "GF256Add(0x%02X, 0x%02X)", tt.a, tt.b)
	}
}

func TestGF256Mul(t *testing.T) {
	// Using AES irreducible polynomial 0x11B (x^8 + x^4 + x^3 + x + 1)
	mod := byte(0x1B)

	tests := []struct {
		a, b, want byte
	}{
		{0x57, 0x83, 0xC1},
		{0x01, 0x57, 0x57},
		{0x00, 0x57, 0x00},
	}

	for _, tt := range tests {
		got, err := GF256Mul(tt.a, tt.b, mod)
		require.NoError(t, err, "GF256Mul(0x%02X, 0x%02X, 0x%02X)", tt.a, tt.b, mod)
		assert.Equal(t, tt.want, got, "GF256Mul(0x%02X, 0x%02X, 0x%02X)", tt.a, tt.b, mod)
	}
}

func TestGF256MulReducible(t *testing.T) {
	// 0x02 is reducible (degree 1)
	_, err := GF256Mul(0x57, 0x83, 0x02)
	require.ErrorIs(t, err, ErrReduciblePolynomial)
}

func TestGF256Inv(t *testing.T) {
	mod := byte(0x1B) // AES polynomial

	tests := []byte{0x01, 0x02, 0x53, 0xCA}

	for _, a := range tests {
		inv, err := GF256Inv(a, mod)
		require.NoError(t, err, "GF256Inv(0x%02X, 0x%02X)", a, mod)

		prod, err := GF256Mul(a, inv, mod)
		require.NoError(t, err)
		assert.Equal(t, byte(0x01), prod, "GF256Inv(0x%02X) = 0x%02X, but 0x%02X * 0x%02X", a, inv, a, inv)
	}
}

func TestGF256InvZero(t *testing.T) {
	_, err := GF256Inv(0x00, 0x1B)
	require.Error(t, err)
}

func TestIsIrreducible(t *testing.T) {
	tests := []struct {
		poly byte
		want bool
	}{
		{0x1B, true},  // x^8 + x^4 + x^3 + x + 1 (AES)
		{0x1D, true},  // x^8 + x^4 + x^3 + x^2 + 1
		{0x02, false}, // x (reducible)
		{0x04, false}, // x^2 (reducible)
		{0xFF, false}, // Has factors
	}

	for _, tt := range tests {
		got := IsIrreducible(tt.poly)
		assert.Equal(t, tt.want, got, "IsIrreducible(0x%02X)", tt.poly)
	}
}

func TestGetAllIrreducible(t *testing.T) {
	irr := GetAllIrreducible()

	assert.NotEmpty(t, irr)

	for _, p := range irr {
		assert.True(t, IsIrreducible(p), "0x%02X is not irreducible", p)
	}

	assert.Contains(t, irr, byte(0x1B), "AES polynomial 0x1B not found")

	t.Logf("Found %d irreducible polynomials of degree 8", len(irr))
}

func TestFactorize(t *testing.T) {
	tests := []struct {
		poly uint16
	}{
		{0x06},  // x^2 + x = x(x+1)
		{0x0F},  // x^3 + x^2 + x + 1
		{0x1B},  // irreducible
		{0x100}, // x^8
	}

	for _, tt := range tests {
		factors := Factorize(tt.poly)
		t.Logf("Factorize(0x%03X) = %v", tt.poly, factors)

		// Verify factorization by multiplying factors
		if len(factors) > 0 {
			product := uint16(1)
			for _, f := range factors {
				product = polyMul(product, f)
			}
			assert.Equal(t, tt.poly, product, "Product of factors")
		}
	}
}

func TestPolyDegree(t *testing.T) {
	tests := []struct {
		poly uint16
		want int
	}{
		{0x00, -1},
		{0x01, 0},
		{0x02, 1},
		{0x04, 2},
		{0x100, 8},
		{0x1FF, 8},
	}

	for _, tt := range tests {
		got := polyDegree(tt.poly)
		assert.Equal(t, tt.want, got, "polyDegree(0x%03X)", tt.poly)
	}
}
