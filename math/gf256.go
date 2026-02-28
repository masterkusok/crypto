package math

import "errors"

var ErrReduciblePolynomial = errors.New("polynomial is reducible")

func GF256Add(a, b byte) byte {
	return a ^ b
}

func GF256Mul(a, b, mod byte) (byte, error) {
	if !IsIrreducible(mod) {
		return 0, ErrReduciblePolynomial
	}

	result := byte(0)
	for i := 0; i < 8; i++ {
		if b&1 == 1 {
			result ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= mod
		}
		b >>= 1
	}
	return result, nil
}

func GF256Inv(a, mod byte) (byte, error) {
	if a == 0 {
		return 0, errors.New("zero has no inverse")
	}
	if !IsIrreducible(mod) {
		return 0, ErrReduciblePolynomial
	}

	fullMod := uint16(0x100) | uint16(mod)
	r0, r1 := fullMod, uint16(a)
	t0, t1 := uint16(0), uint16(1)

	for r1 != 0 {
		q := polyDiv(r0, r1)
		r0, r1 = r1, polyAdd(r0, polyMul(q, r1))
		t0, t1 = t1, polyAdd(t0, polyMul(q, t1))
	}

	return byte(t0), nil
}

func IsIrreducible(poly byte) bool {
	fullPoly := uint16(0x100) | uint16(poly)

	for d := 1; d <= 4; d++ {
		for p := uint16(1 << d); p < uint16(1<<(d+1)); p++ {
			if polyDegree(p) == d && polyMod(fullPoly, p) == 0 {
				return false
			}
		}
	}
	return true
}

func GetAllIrreducible() []byte {
	var result []byte
	for p := 0; p < 256; p++ {
		if IsIrreducible(byte(p)) {
			result = append(result, byte(p))
		}
	}
	return result
}

func Factorize(poly uint16) []uint16 {
	if poly == 0 || poly == 1 {
		return nil
	}

	var factors []uint16

	for poly&1 == 0 {
		factors = append(factors, 0x02)
		poly >>= 1
	}

	for d := 2; d <= polyDegree(poly); d++ {
		for p := uint16(1 << d); p < uint16(1<<(d+1)); p++ {
			if polyDegree(p) != d {
				continue
			}

			for poly > 1 && polyMod(poly, p) == 0 {
				factors = append(factors, p)
				poly = polyDiv(poly, p)
			}
		}
	}

	if poly > 1 {
		factors = append(factors, poly)
	}

	return factors
}

func polyDegree(p uint16) int {
	if p == 0 {
		return -1
	}
	deg := 0
	for p > 1 {
		p >>= 1
		deg++
	}
	return deg
}

func polyAdd(a, b uint16) uint16 {
	return a ^ b
}

func polyMul(a, b uint16) uint16 {
	result := uint16(0)
	for b != 0 {
		if b&1 == 1 {
			result ^= a
		}
		a <<= 1
		b >>= 1
	}
	return result
}

func polyMod(a, b uint16) uint16 {
	if b == 0 {
		return a
	}
	degB := polyDegree(b)
	for {
		degA := polyDegree(a)
		if degA < degB {
			return a
		}
		a ^= b << (degA - degB)
	}
}

func polyDiv(a, b uint16) uint16 {
	if b == 0 {
		return 0
	}
	result := uint16(0)
	degB := polyDegree(b)
	for {
		degA := polyDegree(a)
		if degA < degB {
			return result
		}
		shift := degA - degB
		result ^= 1 << shift
		a ^= b << shift
	}
}
