package des

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDESEncryptDecrypt(t *testing.T) {
	ctx := context.Background()
	des := NewDES()

	key := []byte{0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1}
	plaintext := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF}

	require.NoError(t, des.SetKey(ctx, key))

	encrypted, err := des.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := des.Decrypt(ctx, encrypted)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}
