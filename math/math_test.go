package math

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLegendre(t *testing.T) {
	tests := []struct {
		a, p string
		want int
	}{
		{"2", "7", 1},
		{"3", "7", -1},
		{"5", "11", 1},
		{"7", "11", -1},
		{"0", "5", 0},
		{"10", "5", 0},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		p := new(big.Int)
		p.SetString(tt.p, 10)
		got := Legendre(a, p)
		assert.Equal(t, tt.want, got, "Legendre(%s, %s)", tt.a, tt.p)
	}
}

func TestJacobi(t *testing.T) {
	tests := []struct {
		a, n string
		want int
	}{
		{"1", "1", 1},
		{"2", "15", 1},
		{"5", "9", 1},
		{"6", "9", 0},
		{"1001", "9907", -1},
		{"19", "45", 1},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		n := new(big.Int)
		n.SetString(tt.n, 10)
		got := Jacobi(a, n)
		assert.Equal(t, tt.want, got, "Jacobi(%s, %s)", tt.a, tt.n)
	}
}

func TestGCD(t *testing.T) {
	tests := []struct {
		a, b string
		want string
	}{
		{"48", "18", "6"},
		{"100", "35", "5"},
		{"17", "19", "1"},
		{"0", "5", "5"},
		{"-12", "8", "4"},
		{"270", "192", "6"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		b := new(big.Int)
		b.SetString(tt.b, 10)
		want := new(big.Int)
		want.SetString(tt.want, 10)

		got := GCD(a, b)
		assert.Equal(t, 0, got.Cmp(want), "GCD(%s, %s)", tt.a, tt.b)
	}
}

func TestExtendedGCD(t *testing.T) {
	tests := []struct {
		a, b    string
		wantGCD string
	}{
		{"48", "18", "6"},
		{"100", "35", "5"},
		{"17", "19", "1"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		b := new(big.Int)
		b.SetString(tt.b, 10)
		wantGCD := new(big.Int)
		wantGCD.SetString(tt.wantGCD, 10)

		gcd, x, y := ExtendedGCD(a, b)

		assert.Equal(t, 0, gcd.Cmp(wantGCD), "ExtendedGCD(%s, %s) gcd", tt.a, tt.b)

		result := new(big.Int).Mul(a, x)
		result.Add(result, new(big.Int).Mul(b, y))
		assert.Equal(t, 0, result.Cmp(gcd), "Bezout identity: %s*%v + %s*%v", tt.a, x, tt.b, y)
	}
}

func TestModPow(t *testing.T) {
	tests := []struct {
		base, exp, m string
		want         string
	}{
		{"2", "10", "1000", "24"},
		{"3", "5", "7", "5"},
		{"5", "3", "13", "8"},
		{"2", "100", "97", "16"},
		{"7", "0", "13", "1"},
		{"10", "5", "1", "0"},
	}

	for _, tt := range tests {
		base := new(big.Int)
		base.SetString(tt.base, 10)
		exp := new(big.Int)
		exp.SetString(tt.exp, 10)
		m := new(big.Int)
		m.SetString(tt.m, 10)
		want := new(big.Int)
		want.SetString(tt.want, 10)

		got := ModPow(base, exp, m)
		assert.Equal(t, 0, got.Cmp(want), "ModPow(%s, %s, %s)", tt.base, tt.exp, tt.m)
	}
}

func TestModInverse(t *testing.T) {
	tests := []struct {
		a, m string
		want string
	}{
		{"3", "11", "4"},
		{"7", "26", "15"},
		{"17", "43", "38"},
	}

	for _, tt := range tests {
		a := new(big.Int)
		a.SetString(tt.a, 10)
		m := new(big.Int)
		m.SetString(tt.m, 10)
		want := new(big.Int)
		want.SetString(tt.want, 10)

		inv := ModInverse(a, m)

		assert.NotNil(t, inv, "ModInverse(%s, %s)", tt.a, tt.m)
		assert.Equal(t, 0, inv.Cmp(want), "ModInverse(%s, %s)", tt.a, tt.m)

		result := new(big.Int).Mul(a, inv)
		result.Mod(result, m)
		assert.Equal(t, 0, result.Cmp(big.NewInt(1)), "Verification: (%s * %v) mod %s", tt.a, inv, tt.m)
	}
}

func TestModInverseNoInverse(t *testing.T) {
	a := big.NewInt(6)
	m := big.NewInt(9)

	inv := ModInverse(a, m)

	assert.Nil(t, inv)
}
