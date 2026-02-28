package dh

import (
	"math/big"
	"testing"

	cryptoMath "github.com/masterkusok/crypto/math"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateParameters(t *testing.T) {
	params, err := GenerateParameters(256, cryptoMath.NewMillerRabinTest(), 0.99)
	require.NoError(t, err)
	require.NotNil(t, params)
	assert.NotNil(t, params.P)
	assert.NotNil(t, params.G)
	assert.Equal(t, int64(2), params.G.Int64())
}

func TestGenerateKey(t *testing.T) {
	params, err := GenerateParameters(256, cryptoMath.NewMillerRabinTest(), 0.99)
	require.NoError(t, err)

	priv, pub, err := GenerateKey(params)
	require.NoError(t, err)
	require.NotNil(t, priv)
	require.NotNil(t, pub)

	assert.NotNil(t, priv.X)
	assert.NotNil(t, pub.Y)
	assert.True(t, priv.X.Cmp(big.NewInt(1)) > 0)
	assert.True(t, priv.X.Cmp(params.P) < 0)
	assert.True(t, pub.Y.Cmp(big.NewInt(1)) > 0)
	assert.True(t, pub.Y.Cmp(params.P) < 0)
}

func TestKeyExchange(t *testing.T) {
	params, err := GenerateParameters(256, cryptoMath.NewMillerRabinTest(), 0.99)
	require.NoError(t, err)

	// Alice generates key pair
	alicePriv, alicePub, err := GenerateKey(params)
	require.NoError(t, err)

	// Bob generates key pair
	bobPriv, bobPub, err := GenerateKey(params)
	require.NoError(t, err)

	// Alice computes shared secret
	aliceSecret, err := ComputeSharedSecret(alicePriv, bobPub)
	require.NoError(t, err)

	// Bob computes shared secret
	bobSecret, err := ComputeSharedSecret(bobPriv, alicePub)
	require.NoError(t, err)

	// Secrets should match
	assert.Equal(t, 0, aliceSecret.Cmp(bobSecret))
}

func TestInvalidPublicKey(t *testing.T) {
	params, err := GenerateParameters(256, cryptoMath.NewMillerRabinTest(), 0.99)
	require.NoError(t, err)

	priv, _, err := GenerateKey(params)
	require.NoError(t, err)

	// Invalid public key: y = 1
	invalidPub := &PublicKey{Params: params, Y: big.NewInt(1)}
	_, err = ComputeSharedSecret(priv, invalidPub)
	require.Error(t, err)

	// Invalid public key: y = p
	invalidPub = &PublicKey{Params: params, Y: new(big.Int).Set(params.P)}
	_, err = ComputeSharedSecret(priv, invalidPub)
	require.Error(t, err)
}

func TestParameterMismatch(t *testing.T) {
	params1, err := GenerateParameters(256, cryptoMath.NewMillerRabinTest(), 0.99)
	require.NoError(t, err)

	params2, err := GenerateParameters(256, cryptoMath.NewMillerRabinTest(), 0.99)
	require.NoError(t, err)

	priv1, _, err := GenerateKey(params1)
	require.NoError(t, err)

	_, pub2, err := GenerateKey(params2)
	require.NoError(t, err)

	_, err = ComputeSharedSecret(priv1, pub2)
	require.Error(t, err)
}

func TestNilParameters(t *testing.T) {
	_, _, err := GenerateKey(nil)
	require.Error(t, err)

	_, _, err = GenerateKey(&Parameters{})
	require.Error(t, err)
}
