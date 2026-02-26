package math

import "math/big"

func Legendre(a, p int64) int {
	return Jacobi(a, p)
}

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

func ModInverseBig(a, m *big.Int) *big.Int {
	gcd, x, _ := ExtendedGCDBig(a, m)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	x.Mod(x, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}

	return x
}

func ModPowBig(base, exp, m *big.Int) *big.Int {
	if m.Cmp(big.NewInt(1)) == 0 {
		return big.NewInt(0)
	}

	result := big.NewInt(1)
	base = new(big.Int).Mod(base, m)
	exp = new(big.Int).Set(exp)

	for exp.Sign() > 0 {
		if new(big.Int).And(exp, big.NewInt(1)).Cmp(big.NewInt(1)) == 0 {
			result.Mul(result, base)
			result.Mod(result, m)
		}
		exp.Rsh(exp, 1)
		base.Mul(base, base)
		base.Mod(base, m)
	}

	return result
}
