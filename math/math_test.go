package math

import (
	"math/big"
	"testing"
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
		if got != tt.want {
			t.Errorf("Legendre(%d, %d) = %d, want %d", tt.a, tt.p, got, tt.want)
		}
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
		if got != tt.want {
			t.Errorf("Jacobi(%d, %d) = %d, want %d", tt.a, tt.n, got, tt.want)
		}
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
		if got != tt.want {
			t.Errorf("GCD(%d, %d) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
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
		if gcd != tt.wantGCD {
			t.Errorf("ExtendedGCD(%d, %d) gcd = %d, want %d", tt.a, tt.b, gcd, tt.wantGCD)
		}
		if tt.checkBezout {
			if tt.a*x+tt.b*y != gcd {
				t.Errorf("ExtendedGCD(%d, %d): Bezout identity failed: %d*%d + %d*%d = %d, want %d",
					tt.a, tt.b, tt.a, x, tt.b, y, tt.a*x+tt.b*y, gcd)
			}
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
		if got != tt.want {
			t.Errorf("ModPow(%d, %d, %d) = %d, want %d", tt.base, tt.exp, tt.m, got, tt.want)
		}
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
		
		if gcd.Cmp(big.NewInt(tt.wantGCD)) != 0 {
			t.Errorf("ExtendedGCDBig(%d, %d) gcd = %v, want %d", tt.a, tt.b, gcd, tt.wantGCD)
		}
		
		// Verify Bezout identity: ax + by = gcd
		result := new(big.Int).Mul(a, x)
		result.Add(result, new(big.Int).Mul(b, y))
		
		if result.Cmp(gcd) != 0 {
			t.Errorf("Bezout identity failed: %d*%v + %d*%v = %v, want %v", tt.a, x, tt.b, y, result, gcd)
		}
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
		
		if inv == nil {
			t.Errorf("ModInverseBig(%d, %d) returned nil", tt.a, tt.m)
			continue
		}
		
		if inv.Cmp(big.NewInt(tt.want)) != 0 {
			t.Errorf("ModInverseBig(%d, %d) = %v, want %d", tt.a, tt.m, inv, tt.want)
		}
		
		// Verify: (a * inv) mod m = 1
		result := new(big.Int).Mul(a, inv)
		result.Mod(result, m)
		
		if result.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("Verification failed: (%d * %v) mod %d = %v, want 1", tt.a, inv, tt.m, result)
		}
	}
}

func TestModInverseBigNoInverse(t *testing.T) {
	// gcd(6, 9) = 3, so no inverse exists
	a := big.NewInt(6)
	m := big.NewInt(9)
	
	inv := ModInverseBig(a, m)
	
	if inv != nil {
		t.Errorf("ModInverseBig(6, 9) should return nil, got %v", inv)
	}
}
