package rsa

import (
	"math/big"
)

// WienerAttack attempts to recover private key d using Wiener's attack.
// Returns d if successful, nil otherwise.
// Attack works when d < N^(1/4) / 3
func WienerAttack(pub *PublicKey) *big.Int {
	// Compute continued fraction expansion of e/N
	convergents := continuedFraction(pub.E, pub.N)

	for _, conv := range convergents {
		k := conv[0]
		d := conv[1]

		if k.Cmp(big.NewInt(0)) == 0 {
			continue
		}

		// Check if this d works: e*d ≡ 1 (mod φ(N))
		// We can verify by checking if (e*d - 1) / k gives us φ(N)
		ed := new(big.Int).Mul(pub.E, d)
		ed.Sub(ed, big.NewInt(1))

		if new(big.Int).Mod(ed, k).Cmp(big.NewInt(0)) != 0 {
			continue
		}

		phi := new(big.Int).Div(ed, k)

		// Try to factor N using φ(N)
		// N = p*q, φ(N) = (p-1)(q-1) = N - p - q + 1
		// So: p + q = N - φ(N) + 1
		pPlusQ := new(big.Int).Sub(pub.N, phi)
		pPlusQ.Add(pPlusQ, big.NewInt(1))

		// Solve: p + q = pPlusQ, p*q = N
		// p = (pPlusQ ± sqrt(pPlusQ^2 - 4N)) / 2
		discriminant := new(big.Int).Mul(pPlusQ, pPlusQ)
		discriminant.Sub(discriminant, new(big.Int).Mul(big.NewInt(4), pub.N))

		if discriminant.Sign() < 0 {
			continue
		}

		sqrtD := new(big.Int).Sqrt(discriminant)
		if new(big.Int).Mul(sqrtD, sqrtD).Cmp(discriminant) != 0 {
			continue
		}

		p := new(big.Int).Add(pPlusQ, sqrtD)
		p.Div(p, big.NewInt(2))

		q := new(big.Int).Sub(pPlusQ, sqrtD)
		q.Div(q, big.NewInt(2))

		// Verify
		if new(big.Int).Mul(p, q).Cmp(pub.N) == 0 {
			return d
		}
	}

	return nil
}

// continuedFraction computes convergents of continued fraction expansion of a/b.
func continuedFraction(a, b *big.Int) [][2]*big.Int {
	var convergents [][2]*big.Int

	n0 := big.NewInt(0)
	n1 := big.NewInt(1)
	d0 := big.NewInt(1)
	d1 := big.NewInt(0)

	x := new(big.Int).Set(a)
	y := new(big.Int).Set(b)

	for i := 0; i < 10000 && y.Cmp(big.NewInt(0)) > 0; i++ {
		q := new(big.Int).Div(x, y)

		// Update convergents
		n2 := new(big.Int).Mul(q, n1)
		n2.Add(n2, n0)

		d2 := new(big.Int).Mul(q, d1)
		d2.Add(d2, d0)

		convergents = append(convergents, [2]*big.Int{n2, d2})

		// Update for next iteration
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
	// Vulnerable if d < N^(1/4) / 3
	nSqrt := new(big.Int).Sqrt(pub.N)
	nFourthRoot := new(big.Int).Sqrt(nSqrt)
	threshold := new(big.Int).Div(nFourthRoot, big.NewInt(3))

	// We can't check d directly without private key, but we can try the attack
	d := WienerAttack(pub)
	return d != nil && d.Cmp(threshold) < 0
}
