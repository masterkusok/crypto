package math

import (
	"testing"
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
		if got != tt.want {
			t.Errorf("GF256Add(0x%02X, 0x%02X) = 0x%02X, want 0x%02X", tt.a, tt.b, got, tt.want)
		}
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
		if err != nil {
			t.Errorf("GF256Mul(0x%02X, 0x%02X, 0x%02X) error: %v", tt.a, tt.b, mod, err)
			continue
		}
		if got != tt.want {
			t.Errorf("GF256Mul(0x%02X, 0x%02X, 0x%02X) = 0x%02X, want 0x%02X", tt.a, tt.b, mod, got, tt.want)
		}
	}
}

func TestGF256MulReducible(t *testing.T) {
	// 0x02 is reducible (degree 1)
	_, err := GF256Mul(0x57, 0x83, 0x02)
	if err != ErrReduciblePolynomial {
		t.Errorf("Expected ErrReduciblePolynomial, got %v", err)
	}
}

func TestGF256Inv(t *testing.T) {
	mod := byte(0x1B) // AES polynomial

	tests := []byte{0x01, 0x02, 0x53, 0xCA}

	for _, a := range tests {
		inv, err := GF256Inv(a, mod)
		if err != nil {
			t.Errorf("GF256Inv(0x%02X, 0x%02X) error: %v", a, mod, err)
			continue
		}

		// Verify: a * inv = 1
		prod, err := GF256Mul(a, inv, mod)
		if err != nil {
			t.Errorf("Verification mul error: %v", err)
			continue
		}
		if prod != 0x01 {
			t.Errorf("GF256Inv(0x%02X) = 0x%02X, but 0x%02X * 0x%02X = 0x%02X, want 0x01",
				a, inv, a, inv, prod)
		}
	}
}

func TestGF256InvZero(t *testing.T) {
	_, err := GF256Inv(0x00, 0x1B)
	if err == nil {
		t.Error("Expected error for inverse of zero")
	}
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
		if got != tt.want {
			t.Errorf("IsIrreducible(0x%02X) = %v, want %v", tt.poly, got, tt.want)
		}
	}
}

func TestGetAllIrreducible(t *testing.T) {
	irr := GetAllIrreducible()

	if len(irr) == 0 {
		t.Error("No irreducible polynomials found")
	}

	// Verify all returned polynomials are irreducible
	for _, p := range irr {
		if !IsIrreducible(p) {
			t.Errorf("0x%02X is not irreducible", p)
		}
	}

	// Check that 0x1B (AES polynomial) is in the list
	found := false
	for _, p := range irr {
		if p == 0x1B {
			found = true
			break
		}
	}
	if !found {
		t.Error("AES polynomial 0x1B not found in irreducible list")
	}

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
			if product != tt.poly {
				t.Errorf("Product of factors = 0x%03X, want 0x%03X", product, tt.poly)
			}
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
		if got != tt.want {
			t.Errorf("polyDegree(0x%03X) = %d, want %d", tt.poly, got, tt.want)
		}
	}
}
