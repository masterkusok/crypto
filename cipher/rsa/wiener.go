package rsa

import "math/big"

// Convergent represents a convergent (numerator/denominator) of continued fraction.
type Convergent struct {
	Numerator   *big.Int
	Denominator *big.Int
}

// WienerAttackResult contains results of Wiener attack.
type WienerAttackResult struct {
	D           *big.Int      // Private exponent
	Phi         *big.Int      // Euler's totient function φ(N)
	Convergents []Convergent  // All computed convergents
	Success     bool          // Whether attack succeeded
}

// WienerAttack performs Wiener's attack on RSA public key.
// Returns private exponent d, φ(N), and all convergents if successful.
func WienerAttack(pub *PublicKey) *WienerAttackResult {
	result := &WienerAttackResult{
		Convergents: make([]Convergent, 0),
	}

	convergents := continuedFraction(pub.E, pub.N)
	result.Convergents = convergents

	for _, conv := range convergents {
		k := conv.Numerator
		d := conv.Denominator

		if k.Cmp(big.NewInt(0)) == 0 || d.Cmp(big.NewInt(0)) == 0 {
			continue
		}

		// Check if ed ≡ 1 (mod φ), i.e., ed = 1 + kφ
		// So φ = (ed - 1) / k
		ed := new(big.Int).Mul(pub.E, d)
		ed.Sub(ed, big.NewInt(1))

		if new(big.Int).Mod(ed, k).Cmp(big.NewInt(0)) != 0 {
			continue
		}

		phi := new(big.Int).Div(ed, k)

		// φ(N) must be less than N
		if phi.Cmp(pub.N) >= 0 {
			continue
		}

		// φ(N) = (p-1)(q-1) = N - (p+q) + 1
		// So p + q = N - φ + 1
		pPlusQ := new(big.Int).Sub(pub.N, phi)
		pPlusQ.Add(pPlusQ, big.NewInt(1))

		// p and q are roots of x² - (p+q)x + N = 0
		// discriminant = (p+q)² - 4N = (p-q)²
		discriminant := new(big.Int).Mul(pPlusQ, pPlusQ)
		discriminant.Sub(discriminant, new(big.Int).Lsh(pub.N, 2))

		if discriminant.Sign() < 0 {
			continue
		}

		// Check if discriminant is perfect square
		sqrtD := new(big.Int).Sqrt(discriminant)
		if new(big.Int).Mul(sqrtD, sqrtD).Cmp(discriminant) != 0 {
			continue
		}

		// p = ((p+q) + sqrt(discriminant)) / 2
		// q = ((p+q) - sqrt(discriminant)) / 2
		p := new(big.Int).Add(pPlusQ, sqrtD)
		p.Rsh(p, 1)

		q := new(big.Int).Sub(pPlusQ, sqrtD)
		q.Rsh(q, 1)

		// Verify that p * q = N
		if new(big.Int).Mul(p, q).Cmp(pub.N) == 0 {
			result.D = d
			result.Phi = phi
			result.Success = true
			return result
		}
	}

	return result
}

// continuedFraction computes convergents of continued fraction expansion of e/N.
func continuedFraction(e, n *big.Int) []Convergent {
	var convergents []Convergent

	n0 := big.NewInt(0)
	n1 := big.NewInt(1)
	d0 := big.NewInt(1)
	d1 := big.NewInt(0)

	x := new(big.Int).Set(e)
	y := new(big.Int).Set(n)

	for i := 0; i < 10000 && y.Cmp(big.NewInt(0)) > 0; i++ {
		q := new(big.Int).Div(x, y)

		// Update convergents: n_i = q * n_{i-1} + n_{i-2}
		n2 := new(big.Int).Mul(q, n1)
		n2.Add(n2, n0)

		d2 := new(big.Int).Mul(q, d1)
		d2.Add(d2, d0)

		convergents = append(convergents, Convergent{
			Numerator:   new(big.Int).Set(n2),
			Denominator: new(big.Int).Set(d2),
		})

		n0, n1 = n1, n2
		d0, d1 = d1, d2

		// x, y = y, x mod y
		tmp := new(big.Int).Mod(x, y)
		x = y
		y = tmp
	}

	return convergents
}

// IsVulnerableToWiener checks if public key is vulnerable to Wiener attack.
func IsVulnerableToWiener(pub *PublicKey) bool {
	result := WienerAttack(pub)
	if !result.Success {
		return false
	}

	// Vulnerable if d < N^(1/4) / 3
	nSqrt := new(big.Int).Sqrt(pub.N)
	nFourthRoot := new(big.Int).Sqrt(nSqrt)
	threshold := new(big.Int).Div(nFourthRoot, big.NewInt(3))

	return result.D.Cmp(threshold) < 0
}
