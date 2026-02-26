package tripledes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTripleDESThreeKeys(t *testing.T) {
	ctx := context.Background()
	tdes := NewTripleDES()

	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
		0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
	}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	require.NoError(t, tdes.SetKey(ctx, key))

	encrypted, err := tdes.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := tdes.Decrypt(ctx, encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestTripleDESTwoKeys(t *testing.T) {
	ctx := context.Background()
	tdes := NewTripleDES()

	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	require.NoError(t, tdes.SetKey(ctx, key))

	encrypted, err := tdes.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)

	decrypted, err := tdes.Decrypt(ctx, encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestTripleDESInvalidKeySize(t *testing.T) {
	ctx := context.Background()
	tdes := NewTripleDES()

	err := tdes.SetKey(ctx, []byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestTripleDESBlockSize(t *testing.T) {
	tdes := NewTripleDES()
	assert.Equal(t, 8, tdes.BlockSize())
}
