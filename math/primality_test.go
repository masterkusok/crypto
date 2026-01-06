package math

import "testing"

var primes = []int64{2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97}
var composites = []int64{4, 6, 8, 9, 10, 12, 14, 15, 16, 18, 20, 21, 22, 24, 25, 26, 27, 28, 30, 32, 33, 34, 35, 36}

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
		if !tester.IsProbablyPrime(p, minProb) {
			t.Errorf("%s: %d should be prime", name, p)
		}
	}

	for _, c := range composites {
		if tester.IsProbablyPrime(c, minProb) {
			t.Errorf("%s: %d should be composite", name, c)
		}
	}
}

func TestEdgeCases(t *testing.T) {
	tests := []PrimalityTester{
		NewFermatTest(),
		NewSolovayStrassenTest(),
		NewMillerRabinTest(),
	}

	for _, test := range tests {
		if test.IsProbablyPrime(0, 0.99) {
			t.Error("0 should not be prime")
		}
		if test.IsProbablyPrime(1, 0.99) {
			t.Error("1 should not be prime")
		}
		if !test.IsProbablyPrime(2, 0.99) {
			t.Error("2 should be prime")
		}
	}
}

func TestLargePrimes(t *testing.T) {
	largePrimes := []int64{104729, 1299709, 15485863}
	tests := []PrimalityTester{
		NewFermatTest(),
		NewSolovayStrassenTest(),
		NewMillerRabinTest(),
	}

	for _, test := range tests {
		for _, p := range largePrimes {
			if !test.IsProbablyPrime(p, 0.999) {
				t.Errorf("%d should be prime", p)
			}
		}
	}
}
