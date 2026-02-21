package math

import (
	cryptoRand "crypto/rand"
	"math"
	"math/big"
	"math/rand"
)

type PrimalityTester interface {
	IsProbablyPrime(n int64, minProbability float64) bool
}

type testFunc func(n, witness int64) bool

type primalityTest struct {
	test testFunc
}

func (p *primalityTest) IsProbablyPrime(n int64, minProbability float64) bool {
	if n < 2 {
		return false
	}
	if n == 2 || n == 3 {
		return true
	}
	if n%2 == 0 {
		return false
	}

	k := int(math.Ceil(math.Log(1-minProbability) / math.Log(0.5)))
	for i := 0; i < k; i++ {
		witness := rand.Int63n(n-2) + 2
		if !p.test(n, witness) {
			return false
		}
	}

	return true
}

func NewFermatTest() PrimalityTester {
	return &primalityTest{
		test: func(n, a int64) bool {
			return ModPow(a, n-1, n) == 1
		},
	}
}

func NewSolovayStrassenTest() PrimalityTester {
	return &primalityTest{
		test: func(n, a int64) bool {
			if GCD(a, n) > 1 {
				return false
			}

			jacobi := int64(Jacobi(a, n))
			if jacobi == -1 {
				jacobi = n - 1
			}

			return ModPow(a, (n-1)/2, n) == jacobi
		},
	}
}

func NewMillerRabinTest() PrimalityTester {
	return &primalityTest{
		test: func(n, a int64) bool {
			d := n - 1
			r := int64(0)
			for d%2 == 0 {
				d /= 2
				r++
			}

			x := ModPow(a, d, n)
			if x == 1 || x == n-1 {
				return true
			}

			for i := int64(0); i < r-1; i++ {
				x = ModPow(x, 2, n)
				if x == n-1 {
					return true
				}
			}
			return false
		},
	}
}

type PrimalityTesterBig interface {
	IsProbablyPrimeBig(n *big.Int, minProbability float64) bool
}

type testFuncBig func(n, witness *big.Int) bool

type primalityTestBig struct {
	test testFuncBig
}

func (p *primalityTestBig) IsProbablyPrimeBig(n *big.Int, minProbability float64) bool {
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

	k := int(math.Ceil(math.Log(1-minProbability) / math.Log(0.5)))
	for i := 0; i < k; i++ {
		witness, _ := cryptoRand.Int(cryptoRand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		witness.Add(witness, two)
		if !p.test(n, witness) {
			return false
		}
	}
	return true
}

func NewMillerRabinTestBig() PrimalityTesterBig {
	return &primalityTestBig{
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
