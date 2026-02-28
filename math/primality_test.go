package math

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

var primes = []string{"2", "3", "5", "7", "11", "13", "17", "19", "23", "29", "31", "37", "41", "43", "47", "53", "59", "61", "67", "71", "73", "79", "83", "89", "97"}
var composites = []string{"4", "6", "8", "9", "10", "12", "14", "15", "16", "18", "20", "21", "22", "24", "25", "26", "27", "28", "30", "32", "33", "34", "35", "36"}

func TestFermatTest(t *testing.T) {
	test := NewFermatTest()
	testPrimalityTester(t, test, "Fermat")
}

func TestSolovayStrassenTest(t *testing.T) {
	test := NewSolovayStrassenTest()
	testPrimalityTester(t, test, "Solovay-Strassen")
}

func TestMillerRabinTest(t *testing.T) {
	test := NewMillerRabinTest()
	testPrimalityTester(t, test, "Miller-Rabin")
}

func testPrimalityTester(t *testing.T, tester PrimalityTester, name string) {
	minProb := 0.99

	for _, p := range primes {
		n := new(big.Int)
		n.SetString(p, 10)
		assert.True(t, tester.IsProbablyPrime(n, minProb), "%s: %s should be prime", name, p)
	}

	for _, c := range composites {
		n := new(big.Int)
		n.SetString(c, 10)
		assert.False(t, tester.IsProbablyPrime(n, minProb), "%s: %s should be composite", name, c)
	}
}

func TestEdgeCases(t *testing.T) {
	tests := []PrimalityTester{
		NewFermatTest(),
		NewSolovayStrassenTest(),
		NewMillerRabinTest(),
	}

	for _, test := range tests {
		assert.False(t, test.IsProbablyPrime(big.NewInt(0), 0.99), "0 should not be prime")
		assert.False(t, test.IsProbablyPrime(big.NewInt(1), 0.99), "1 should not be prime")
		assert.True(t, test.IsProbablyPrime(big.NewInt(2), 0.99), "2 should be prime")
	}
}

func TestLargePrimes(t *testing.T) {
	largePrimes := []string{"104729", "1299709", "15485863"}
	tests := []PrimalityTester{
		NewFermatTest(),
		NewSolovayStrassenTest(),
		NewMillerRabinTest(),
	}

	for _, test := range tests {
		for _, p := range largePrimes {
			n := new(big.Int)
			n.SetString(p, 10)
			assert.True(t, test.IsProbablyPrime(n, 0.999), "%s should be prime", p)
		}
	}
}
