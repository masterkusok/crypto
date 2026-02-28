package math

import "math/big"

func Legendre(a, p *big.Int) int {
	return Jacobi(a, p)
}

func Jacobi(a, n *big.Int) int {
	if n.Cmp(big.NewInt(1)) == 0 {
		return 1
	}

	if a.Sign() == 0 {
		return 0
	}

	if a.Sign() < 0 {
		return jacobi2(n) * Jacobi(new(big.Int).Neg(a), n)
	}

	if new(big.Int).Mod(a, big.NewInt(2)).Sign() == 0 {
		return Jacobi(new(big.Int).Div(a, big.NewInt(2)), n) * jacobi2(n)
	}

	if a.Cmp(n) >= 0 {
		return Jacobi(new(big.Int).Mod(a, n), n)
	}

	aMinus1 := new(big.Int).Sub(a, big.NewInt(1))
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
	if new(big.Int).Div(new(big.Int).Mul(aMinus1, nMinus1), big.NewInt(4)).Bit(0) == 1 {
		return -Jacobi(n, a)
	}

	return Jacobi(n, a)
}

func jacobi2(n *big.Int) int {
	mod8 := new(big.Int).Mod(n, big.NewInt(8)).Int64()
	if mod8 == 1 || mod8 == 7 {
		return 1
	}

	return -1
}

func GCD(a, b *big.Int) *big.Int {
	a = new(big.Int).Abs(a)
	b = new(big.Int).Abs(b)

	for b.Sign() != 0 {
		a, b = b, new(big.Int).Mod(a, b)
	}

	return a
}

func ExtendedGCD(a, b *big.Int) (gcd, x, y *big.Int) {
	if b.Cmp(big.NewInt(0)) == 0 {
		return new(big.Int).Set(a), big.NewInt(1), big.NewInt(0)
	}

	gcd, x1, y1 := ExtendedGCD(b, new(big.Int).Mod(a, b))
	x = y1
	y = new(big.Int).Sub(x1, new(big.Int).Mul(new(big.Int).Div(a, b), y1))

	return gcd, x, y
}

func ModInverse(a, m *big.Int) *big.Int {
	gcd, x, _ := ExtendedGCD(a, m)

	if gcd.Cmp(big.NewInt(1)) != 0 {
		return nil
	}

	x.Mod(x, m)
	if x.Sign() < 0 {
		x.Add(x, m)
	}

	return x
}

func ModPow(base, exp, m *big.Int) *big.Int {
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
