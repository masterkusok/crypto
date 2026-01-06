// Package math provides number-theoretic functions.
package math

import "math/big"

// Legendre computes the Legendre symbol (a/p) where p is an odd prime.
// Returns 1 if a is a quadratic residue mod p, -1 if not, 0 if a ≡ 0 (mod p).
func Legendre(a, p int64) int {
	return Jacobi(a, p)
}

// Jacobi computes the Jacobi symbol (a/n) for odd n > 0.
func Jacobi(a, n int64) int {
	if n <= 0 || n%2 == 0 {
		return 0
	}

	a = a % n
	result := 1

	for a != 0 {
		for a%2 == 0 {
			a /= 2
			if n%8 == 3 || n%8 == 5 {
				result = -result
			}
		}
		a, n = n, a
		if a%4 == 3 && n%4 == 3 {
			result = -result
		}
		a = a % n
	}

	if n == 1 {
		return result
	}

	return 0
}

// GCD computes the greatest common divisor of a and b using Euclidean algorithm.
func GCD(a, b int64) int64 {
	if a < 0 {
		a = -a
	}
	if b < 0 {
		b = -b
	}

	for b != 0 {
		a, b = b, a%b
	}
	return a
}

// ExtendedGCD computes GCD(a, b) and finds x, y such that ax + by = gcd(a, b).
// Returns (gcd, x, y).
func ExtendedGCD(a, b int64) (gcd, x, y int64) {
	if b == 0 {
		return a, 1, 0
	}

	x0, x1 := int64(1), int64(0)
	y0, y1 := int64(0), int64(1)

	for b != 0 {
		q := a / b
		a, b = b, a%b
		x0, x1 = x1, x0-q*x1
		y0, y1 = y1, y0-q*y1
	}

	return a, x0, y0
}

// ModPow computes (base^exp) mod m using binary exponentiation.
func ModPow(base, exp, m int64) int64 {
	if m == 1 {
		return 0
	}

	result := int64(1)
	base = base % m

	for exp > 0 {
		if exp%2 == 1 {
			result = (result * base) % m
		}
		exp = exp >> 1
		base = (base * base) % m
	}

	return result
}

// ExtendedGCDBig computes GCD(a, b) and finds x, y such that ax + by = gcd(a, b) for big.Int.
// Returns (gcd, x, y).
func ExtendedGCDBig(a, b *big.Int) (gcd, x, y *big.Int) {
	if b.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}

	x0, x1 := big.NewInt(1), big.NewInt(0)
	y0, y1 := big.NewInt(0), big.NewInt(1)

	aCopy := new(big.Int).Set(a)
	bCopy := new(big.Int).Set(b)

	for bCopy.Cmp(big.NewInt(0)) != 0 {
		q := new(big.Int).Div(aCopy, bCopy)
		aCopy, bCopy = bCopy, new(big.Int).Mod(aCopy, bCopy)

		x0, x1 = x1, new(big.Int).Sub(x0, new(big.Int).Mul(q, x1))
		y0, y1 = y1, new(big.Int).Sub(y0, new(big.Int).Mul(q, y1))
	}

	return aCopy, x0, y0
}

// ModInverseBig computes modular multiplicative inverse of a modulo m using Extended Euclidean algorithm.
// Returns x such that (a * x) ≡ 1 (mod m), or nil if inverse doesn't exist.
func ModInverseBig(a, m *big.Int) *big.Int {
	gcd, x, _ := ExtendedGCDBig(a, m)
	
	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	// Ensure x is positive
	x.Mod(x, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}

	return x
}
