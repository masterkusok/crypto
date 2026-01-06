package math

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLegendre(t *testing.T) {
	tests := []struct {
		a, p int64
		want int
	}{
		{2, 7, 1},
		{3, 7, -1},
		{5, 11, 1},
		{7, 11, -1},
		{0, 5, 0},
		{10, 5, 0},
	}

	for _, tt := range tests {
		got := Legendre(tt.a, tt.p)
		assert.Equal(t, tt.want, got, "Legendre(%d, %d)", tt.a, tt.p)
	}
}

func TestJacobi(t *testing.T) {
	tests := []struct {
		a, n int64
		want int
	}{
		{1, 1, 1},
		{2, 15, 1},
		{5, 9, 1},
		{6, 9, 0},
		{1001, 9907, -1},
		{19, 45, 1},
	}

	for _, tt := range tests {
		got := Jacobi(tt.a, tt.n)
		assert.Equal(t, tt.want, got, "Jacobi(%d, %d)", tt.a, tt.n)
	}
}

func TestGCD(t *testing.T) {
	tests := []struct {
		a, b int64
		want int64
	}{
		{48, 18, 6},
		{100, 35, 5},
		{17, 19, 1},
		{0, 5, 5},
		{-12, 8, 4},
		{270, 192, 6},
	}

	for _, tt := range tests {
		got := GCD(tt.a, tt.b)
		assert.Equal(t, tt.want, got, "GCD(%d, %d)", tt.a, tt.b)
	}
}

func TestExtendedGCD(t *testing.T) {
	tests := []struct {
		a, b     int64
		wantGCD  int64
		checkBezout bool
	}{
		{48, 18, 6, true},
		{100, 35, 5, true},
		{17, 19, 1, true},
		{270, 192, 6, true},
	}

	for _, tt := range tests {
		gcd, x, y := ExtendedGCD(tt.a, tt.b)
		assert.Equal(t, tt.wantGCD, gcd, "ExtendedGCD(%d, %d) gcd", tt.a, tt.b)
		if tt.checkBezout {
			assert.Equal(t, gcd, tt.a*x+tt.b*y, "Bezout identity: %d*%d + %d*%d", tt.a, x, tt.b, y)
		}
	}
}

func TestModPow(t *testing.T) {
	tests := []struct {
		base, exp, m int64
		want         int64
	}{
		{2, 10, 1000, 24},
		{3, 5, 7, 5},
		{5, 3, 13, 8},
		{2, 100, 97, 16},
		{7, 0, 13, 1},
		{10, 5, 1, 0},
	}

	for _, tt := range tests {
		got := ModPow(tt.base, tt.exp, tt.m)
		assert.Equal(t, tt.want, got, "ModPow(%d, %d, %d)", tt.base, tt.exp, tt.m)
	}
}

func TestExtendedGCDBig(t *testing.T) {
	tests := []struct {
		a, b    int64
		wantGCD int64
	}{
		{48, 18, 6},
		{100, 35, 5},
		{17, 19, 1},
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		b := big.NewInt(tt.b)
		
		gcd, x, y := ExtendedGCDBig(a, b)
		
		assert.Equal(t, 0, gcd.Cmp(big.NewInt(tt.wantGCD)), "ExtendedGCDBig(%d, %d) gcd", tt.a, tt.b)
		
		result := new(big.Int).Mul(a, x)
		result.Add(result, new(big.Int).Mul(b, y))
		
		assert.Equal(t, 0, result.Cmp(gcd), "Bezout identity: %d*%v + %d*%v", tt.a, x, tt.b, y)
	}
}

func TestModInverseBig(t *testing.T) {
	tests := []struct {
		a, m int64
		want int64
	}{
		{3, 11, 4},   // 3 * 4 ≡ 1 (mod 11)
		{7, 26, 15},  // 7 * 15 ≡ 1 (mod 26)
		{17, 43, 38}, // 17 * 38 ≡ 1 (mod 43)
	}

	for _, tt := range tests {
		a := big.NewInt(tt.a)
		m := big.NewInt(tt.m)
		
		inv := ModInverseBig(a, m)
		
		assert.NotNil(t, inv, "ModInverseBig(%d, %d)", tt.a, tt.m)
		assert.Equal(t, 0, inv.Cmp(big.NewInt(tt.want)), "ModInverseBig(%d, %d)", tt.a, tt.m)
		
		result := new(big.Int).Mul(a, inv)
		result.Mod(result, m)
		
		assert.Equal(t, 0, result.Cmp(big.NewInt(1)), "Verification: (%d * %v) mod %d", tt.a, inv, tt.m)
	}
}

func TestModInverseBigNoInverse(t *testing.T) {
	// gcd(6, 9) = 3, so no inverse exists
	a := big.NewInt(6)
	m := big.NewInt(9)
	
	inv := ModInverseBig(a, m)
	
	assert.Nil(t, inv)
}
