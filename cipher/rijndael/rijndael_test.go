package rijndael

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRijndael128(t *testing.T) {
	key := []byte{
		0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
		0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
	}
	plaintext := []byte{
		0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
		0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
	}

	r, err := NewRijndael(16, 16, 0x1B)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, r.SetKey(ctx, key))

	ciphertext, err := r.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	t.Logf("Ciphertext: %x", ciphertext)

	decrypted, err := r.Decrypt(ctx, ciphertext)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestRijndael192(t *testing.T) {
	key := make([]byte, 24)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, 24)
	for i := range plaintext {
		plaintext[i] = byte(i * 2)
	}

	r, err := NewRijndael(24, 24, 0x1B)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, r.SetKey(ctx, key))

	ciphertext, err := r.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := r.Decrypt(ctx, ciphertext)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestRijndael256(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := make([]byte, 32)
	for i := range plaintext {
		plaintext[i] = byte(i * 3)
	}

	r, err := NewRijndael(32, 32, 0x1B)
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, r.SetKey(ctx, key))

	ciphertext, err := r.Encrypt(ctx, plaintext)
	require.NoError(t, err)

	decrypted, err := r.Decrypt(ctx, ciphertext)
	require.NoError(t, err)

	assert.Equal(t, plaintext, decrypted)
}

func TestRijndaelDifferentModulus(t *testing.T) {
	irr := []byte{0x1B, 0x1D}

	for _, mod := range irr {
		t.Run("Modulus_0x"+string(rune(mod)), func(t *testing.T) {
			key := make([]byte, 16)
			plaintext := []byte("Test message!!!!")

			r, err := NewRijndael(16, 16, mod)
			require.NoError(t, err)

			ctx := context.Background()
			require.NoError(t, r.SetKey(ctx, key))

			ciphertext, err := r.Encrypt(ctx, plaintext)
			require.NoError(t, err)

			decrypted, err := r.Decrypt(ctx, ciphertext)
			require.NoError(t, err)

			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestRijndaelInvalidSizes(t *testing.T) {
	_, err := NewRijndael(15, 16, 0x1B)
	require.Error(t, err)

	_, err = NewRijndael(16, 15, 0x1B)
	require.Error(t, err)
}

func TestRijndaelReducibleModulus(t *testing.T) {
	_, err := NewRijndael(16, 16, 0x02)
	require.Error(t, err)
}

func TestRijndaelBlockSize(t *testing.T) {
	r, _ := NewRijndael(16, 16, 0x1B)
	assert.Equal(t, 16, r.BlockSize())
}

func TestShiftRowsOffsets(t *testing.T) {
	r128, _ := NewRijndael(16, 16, 0x1B)
	shifts128 := r128.getShiftOffsets()
	assert.Equal(t, [4]int{0, 1, 2, 3}, shifts128, "128-bit block should use shifts [0,1,2,3]")

	r192, _ := NewRijndael(24, 24, 0x1B)
	shifts192 := r192.getShiftOffsets()
	assert.Equal(t, [4]int{0, 1, 2, 3}, shifts192, "192-bit block should use shifts [0,1,2,3]")

	r256, _ := NewRijndael(32, 32, 0x1B)
	shifts256 := r256.getShiftOffsets()
	assert.Equal(t, [4]int{0, 1, 3, 4}, shifts256, "256-bit block should use shifts [0,1,3,4]")
}
