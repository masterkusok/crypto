// Package dh implements Diffie-Hellman key exchange.
package dh

import (
	"crypto/rand"
	"math/big"

	"github.com/masterkusok/crypto/errors"
	cryptoMath "github.com/masterkusok/crypto/math"
)

// Parameters represents Diffie-Hellman parameters (p, g).
type Parameters struct {
	P *big.Int // Prime modulus
	G *big.Int // Generator
}

// PrivateKey represents a DH private key.
type PrivateKey struct {
	Params *Parameters
	X      *big.Int // Private value
}

// PublicKey represents a DH public key.
type PublicKey struct {
	Params *Parameters
	Y      *big.Int // Public value: g^x mod p
}

// GenerateParameters generates DH parameters with a prime p of given bit size.
func GenerateParameters(bits int, tester cryptoMath.PrimalityTesterBig, minProb float64) (*Parameters, error) {
	p, err := generateSafePrime(bits, tester, minProb)
	if err != nil {
		return nil, err
	}

	g := big.NewInt(2)

	return &Parameters{P: p, G: g}, nil
}

// GenerateKey generates a new DH key pair.
func GenerateKey(params *Parameters) (*PrivateKey, *PublicKey, error) {
	if params == nil || params.P == nil || params.G == nil {
		return nil, nil, errors.ErrInvalidParameters
	}

	// Generate private key: 1 < x < p-1
	pMinus2 := new(big.Int).Sub(params.P, big.NewInt(2))
	x, err := rand.Int(rand.Reader, pMinus2)
	if err != nil {
		return nil, nil, errors.Annotate(err, "failed to generate private key: %w")
	}
	x.Add(x, big.NewInt(1))

	// Compute public key: y = g^x mod p
	y := new(big.Int).Exp(params.G, x, params.P)

	priv := &PrivateKey{Params: params, X: x}
	pub := &PublicKey{Params: params, Y: y}

	return priv, pub, nil
}

// ComputeSharedSecret computes the shared secret using private key and peer's public key.
func ComputeSharedSecret(priv *PrivateKey, peerPub *PublicKey) (*big.Int, error) {
	if priv == nil || priv.X == nil || priv.Params == nil {
		return nil, errors.ErrInvalidPrivateKey
	}
	if peerPub == nil || peerPub.Y == nil || peerPub.Params == nil {
		return nil, errors.ErrInvalidPublicKey
	}

	// Verify parameters match
	if priv.Params.P.Cmp(peerPub.Params.P) != 0 || priv.Params.G.Cmp(peerPub.Params.G) != 0 {
		return nil, errors.ErrParameterMismatch
	}

	// Verify peer's public key is valid: 1 < y < p-1
	if peerPub.Y.Cmp(big.NewInt(1)) <= 0 || peerPub.Y.Cmp(priv.Params.P) >= 0 {
		return nil, errors.ErrInvalidPublicKey
	}

	// Compute shared secret: s = y^x mod p
	secret := new(big.Int).Exp(peerPub.Y, priv.X, priv.Params.P)

	return secret, nil
}

func generateSafePrime(bits int, tester cryptoMath.PrimalityTesterBig, minProb float64) (*big.Int, error) {
	for {
		// Generate random odd number
		p, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			return nil, errors.Annotate(err, "failed to generate random number: %w")
		}
		// Set highest bit and make odd
		p.SetBit(p, bits-1, 1)
		p.Or(p, big.NewInt(1))

		// Check if p is prime
		if tester.IsProbablyPrimeBig(p, minProb) {
			return p, nil
		}
	}
}
