package deal_test

import (
	"context"
	"testing"

	"github.com/masterkusok/crypto/cipher/deal"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDEAL(t *testing.T) {
	ctx := context.Background()
	key := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
	}
	plaintext := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	d := deal.NewDEAL()
	err := d.SetKey(ctx, key)
	require.NoError(t, err)

	encrypted, err := d.Encrypt(ctx, plaintext)
	require.NoError(t, err)
	assert.NotEqual(t, plaintext, encrypted)
	assert.Len(t, encrypted, 16)

	decrypted, err := d.Decrypt(ctx, encrypted)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestDEALInvalidKeySize(t *testing.T) {
	ctx := context.Background()
	d := deal.NewDEAL()

	err := d.SetKey(ctx, []byte{0x01, 0x02, 0x03})
	assert.Error(t, err)
}

func TestDEALBlockSize(t *testing.T) {
	d := deal.NewDEAL()
	assert.Equal(t, 16, d.BlockSize())
}
