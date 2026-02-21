package rsa

import (
	"crypto/rand"
	"errors"
	"math/big"

	cryptoMath "github.com/masterkusok/crypto/math"
)

type KeyGenerator struct {
	minProbability float64
	bitLength      int
	tester         cryptoMath.PrimalityTester
	testerBig      cryptoMath.PrimalityTesterBig
}

type PublicKey struct {
	N *big.Int
	E *big.Int
}

type PrivateKey struct {
	PublicKey
	D *big.Int
	P *big.Int
	Q *big.Int
}

type RSA struct {
	KeyGen     *KeyGenerator
	privateKey *PrivateKey
	publicKey  *PublicKey
}

func NewRSA(tester cryptoMath.PrimalityTester, minProbability float64, bitLength int) *RSA {
	return &RSA{
		KeyGen: &KeyGenerator{
			minProbability: minProbability,
			bitLength:      bitLength,
			tester:         tester,
			testerBig:      cryptoMath.NewMillerRabinTestBig(),
		},
	}
}

func (r *RSA) GenerateKeyPair() error {
	p, err := r.KeyGen.generatePrime()
	if err != nil {
		return err
	}

	q, err := r.KeyGen.generatePrime()
	if err != nil {
		return err
	}

	// Protect against Fermat attack: ensure |p-q| is large
	diff := new(big.Int).Sub(p, q)
	diff.Abs(diff)
	minDiff := new(big.Int).Lsh(big.NewInt(1), uint(r.KeyGen.bitLength/2-10))
	if diff.Cmp(minDiff) < 0 {
		return r.GenerateKeyPair()
	}

	n := new(big.Int).Mul(p, q)
	phi := new(big.Int).Mul(
		new(big.Int).Sub(p, big.NewInt(1)),
		new(big.Int).Sub(q, big.NewInt(1)),
	)

	// Choose e = 65537 (common choice)
	e := big.NewInt(65537)

	// Compute d = e^(-1) mod φ using Extended Euclidean algorithm
	d := cryptoMath.ModInverseBig(e, phi)
	if d == nil {
		return errors.New("failed to compute private exponent")
	}

	nSqrt := new(big.Int).Sqrt(n)
	nFourthRoot := new(big.Int).Sqrt(nSqrt)
	threshold := new(big.Int).Div(nFourthRoot, big.NewInt(3))

	if d.Cmp(threshold) <= 0 {
		return r.GenerateKeyPair()
	}

	r.publicKey = &PublicKey{N: n, E: e}
	r.privateKey = &PrivateKey{
		PublicKey: *r.publicKey,
		D:         d,
		P:         p,
		Q:         q,
	}

	return nil
}

func (kg *KeyGenerator) generatePrime() (*big.Int, error) {
	for {
		candidate, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(kg.bitLength)))
		if err != nil {
			return nil, err
		}

		candidate.SetBit(candidate, 0, 1)
		candidate.SetBit(candidate, kg.bitLength-1, 1)

		if kg.bitLength <= 60 && candidate.IsInt64() {
			if kg.tester.IsProbablyPrime(candidate.Int64(), kg.minProbability) {
				return candidate, nil
			}
		} else {
			if kg.testerBig.IsProbablyPrimeBig(candidate, kg.minProbability) {
				return candidate, nil
			}
		}
	}
}

func (r *RSA) Encrypt(message []byte) ([]byte, error) {
	if r.publicKey == nil {
		return nil, errors.New("no public key available")
	}

	m := new(big.Int).SetBytes(message)
	if m.Cmp(r.publicKey.N) >= 0 {
		return nil, errors.New("message too large")
	}

	c := cryptoMath.ModPowBig(m, r.publicKey.E, r.publicKey.N)
	return c.Bytes(), nil
}

func (r *RSA) Decrypt(ciphertext []byte) ([]byte, error) {
	if r.privateKey == nil {
		return nil, errors.New("no private key available")
	}

	c := new(big.Int).SetBytes(ciphertext)
	m := cryptoMath.ModPowBig(c, r.privateKey.D, r.privateKey.N)
	return m.Bytes(), nil
}

func (r *RSA) GetPublicKey() *PublicKey {
	return r.publicKey
}

func (r *RSA) GetPrivateKey() *PrivateKey {
	return r.privateKey
}
