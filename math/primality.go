package math

import (
	cryptoRand "crypto/rand"
	"math"
	"math/big"
)

type PrimalityTester interface {
	IsProbablyPrime(n *big.Int, minProbability float64) bool
}

type testFunc func(n, witness *big.Int) bool

type primalityTest struct {
	test      testFunc
	errorProb float64
}

func (p *primalityTest) IsProbablyPrime(n *big.Int, minProbability float64) bool {
	two := big.NewInt(2)
	if n.Cmp(two) < 0 {
		return false
	}
	if n.Cmp(two) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true
	}
	if new(big.Int).Mod(n, two).Cmp(big.NewInt(0)) == 0 {
		return false
	}

	k := int(math.Ceil(math.Log(1-minProbability) / math.Log(p.errorProb)))
	for i := 0; i < k; i++ {
		witness, _ := cryptoRand.Int(cryptoRand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		witness.Add(witness, two)
		if GCD(witness, n).Cmp(big.NewInt(1)) != 0 {
			return false
		}
		if !p.test(n, witness) {
			return false
		}
	}
	return true
}

func NewMillerRabinTest() PrimalityTester {
	return &primalityTest{
		errorProb: 0.25,
		test: func(n, a *big.Int) bool {
			d := new(big.Int).Sub(n, big.NewInt(1))
			r := 0
			for new(big.Int).Mod(d, big.NewInt(2)).Cmp(big.NewInt(0)) == 0 {
				d.Div(d, big.NewInt(2))
				r++
			}

			x := new(big.Int).Exp(a, d, n)
			nMinus1 := new(big.Int).Sub(n, big.NewInt(1))
			if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(nMinus1) == 0 {
				return true
			}

			for i := 0; i < r-1; i++ {
				x.Exp(x, big.NewInt(2), n)
				if x.Cmp(nMinus1) == 0 {
					return true
				}
			}
			return false
		},
	}
}

func NewFermatTest() PrimalityTester {
	return &primalityTest{
		errorProb: 0.5,
		test: func(n, a *big.Int) bool {
			return new(big.Int).Exp(a, new(big.Int).Sub(n, big.NewInt(1)), n).Cmp(big.NewInt(1)) == 0
		},
	}
}

func NewSolovayStrassenTest() PrimalityTester {
	return &primalityTest{
		errorProb: 0.5,
		test: func(n, a *big.Int) bool {
			jacobi := int64(Jacobi(a, n))
			if jacobi == -1 {
				jacobi = new(big.Int).Sub(n, big.NewInt(1)).Int64()
			}

			return new(big.Int).Exp(a, new(big.Int).Div(new(big.Int).Sub(n, big.NewInt(1)), big.NewInt(2)), n).Cmp(big.NewInt(jacobi)) == 0
		},
	}
}
