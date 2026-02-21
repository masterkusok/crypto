package rsa

import "math/big"

type Convergent struct {
	Numerator   *big.Int
	Denominator *big.Int
}

type WienerAttackResult struct {
	D           *big.Int
	Phi         *big.Int
	Convergents []Convergent
	Success     bool
}

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

		ed := new(big.Int).Mul(pub.E, d)
		ed.Sub(ed, big.NewInt(1))

		if new(big.Int).Mod(ed, k).Cmp(big.NewInt(0)) != 0 {
			continue
		}

		phi := new(big.Int).Div(ed, k)

		if phi.Cmp(pub.N) >= 0 {
			continue
		}

		pPlusQ := new(big.Int).Sub(pub.N, phi)
		pPlusQ.Add(pPlusQ, big.NewInt(1))

		discriminant := new(big.Int).Mul(pPlusQ, pPlusQ)
		discriminant.Sub(discriminant, new(big.Int).Lsh(pub.N, 2))

		if discriminant.Sign() < 0 {
			continue
		}

		sqrtD := new(big.Int).Sqrt(discriminant)
		if new(big.Int).Mul(sqrtD, sqrtD).Cmp(discriminant) != 0 {
			continue
		}

		p := new(big.Int).Add(pPlusQ, sqrtD)
		p.Rsh(p, 1)

		q := new(big.Int).Sub(pPlusQ, sqrtD)
		q.Rsh(q, 1)

		if new(big.Int).Mul(p, q).Cmp(pub.N) == 0 {
			result.D = d
			result.Phi = phi
			result.Success = true
			return result
		}
	}

	return result
}

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

		tmp := new(big.Int).Mod(x, y)
		x = y
		y = tmp
	}

	return convergents
}

func IsVulnerableToWiener(pub *PublicKey) bool {
	result := WienerAttack(pub)
	if !result.Success {
		return false
	}

	nSqrt := new(big.Int).Sqrt(pub.N)
	nFourthRoot := new(big.Int).Sqrt(nSqrt)
	threshold := new(big.Int).Div(nFourthRoot, big.NewInt(3))

	return result.D.Cmp(threshold) < 0
}
