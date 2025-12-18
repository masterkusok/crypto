// Package rc6 implements the RC6 block cipher algorithm.
package rc6

import (
	"context"
	"encoding/binary"
	"math/bits"

	"github.com/masterkusok/crypto/errors"
)

const (
	rc6BlockSize = 16 // 128 bits
	rc6Rounds    = 20
	rc6WordSize  = 32 // bits
	rc6Words     = 4  // number of words in block
)

// RC6 implements the RC6 cipher.
type RC6 struct {
	s []uint32 // expanded key
	r int      // number of rounds
	w int      // word size in bits
}

// NewRC6 creates a new RC6 cipher with default parameters.
func NewRC6() *RC6 {
	return &RC6{
		r: rc6Rounds,
		w: rc6WordSize,
	}
}

// SetKey expands the key for RC6.
func (rc *RC6) SetKey(ctx context.Context, key []byte) error {
	if len(key) == 0 || len(key) > 255 {
		return errors.ErrInvalidKeySize
	}

	rc.s = rc.expandKey(key)
	return nil
}

// expandKey performs RC6 key expansion.
func (rc *RC6) expandKey(key []byte) []uint32 {
	c := (len(key) + 3) / 4
	l := make([]uint32, c)

	for i := 0; i < len(key); i++ {
		l[i/4] |= uint32(key[i]) << (8 * (i % 4))
	}

	s := make([]uint32, 2*rc.r+4)
	s[0] = 0xB7E15163 // P32
	for i := 1; i < len(s); i++ {
		s[i] = s[i-1] + 0x9E3779B9 // Q32
	}

	a, b := uint32(0), uint32(0)
	i, j := 0, 0
	v := 3 * max(c, len(s))

	for k := 0; k < v; k++ {
		a = rotl32(s[i]+a+b, 3)
		s[i] = a
		b = rotl32(l[j]+a+b, int((a+b)&31))
		l[j] = b
		i = (i + 1) % len(s)
		j = (j + 1) % c
	}

	return s
}

// Encrypt encrypts a single block.
func (rc *RC6) Encrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != rc6BlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	a := binary.LittleEndian.Uint32(block[0:4])
	b := binary.LittleEndian.Uint32(block[4:8])
	c := binary.LittleEndian.Uint32(block[8:12])
	d := binary.LittleEndian.Uint32(block[12:16])

	b += rc.s[0]
	d += rc.s[1]

	for i := 1; i <= rc.r; i++ {
		t := rotl32(b*(2*b+1), 5)
		u := rotl32(d*(2*d+1), 5)
		a = rotl32(a^t, int(u&31)) + rc.s[2*i]
		c = rotl32(c^u, int(t&31)) + rc.s[2*i+1]
		a, b, c, d = b, c, d, a
	}

	a += rc.s[2*rc.r+2]
	c += rc.s[2*rc.r+3]

	result := make([]byte, rc6BlockSize)
	binary.LittleEndian.PutUint32(result[0:4], a)
	binary.LittleEndian.PutUint32(result[4:8], b)
	binary.LittleEndian.PutUint32(result[8:12], c)
	binary.LittleEndian.PutUint32(result[12:16], d)

	return result, nil
}

// Decrypt decrypts a single block.
func (rc *RC6) Decrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != rc6BlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	a := binary.LittleEndian.Uint32(block[0:4])
	b := binary.LittleEndian.Uint32(block[4:8])
	c := binary.LittleEndian.Uint32(block[8:12])
	d := binary.LittleEndian.Uint32(block[12:16])

	c -= rc.s[2*rc.r+3]
	a -= rc.s[2*rc.r+2]

	for i := rc.r; i >= 1; i-- {
		a, b, c, d = d, a, b, c
		u := rotl32(d*(2*d+1), 5)
		t := rotl32(b*(2*b+1), 5)
		c = rotr32(c-rc.s[2*i+1], int(t&31)) ^ u
		a = rotr32(a-rc.s[2*i], int(u&31)) ^ t
	}

	d -= rc.s[1]
	b -= rc.s[0]

	result := make([]byte, rc6BlockSize)
	binary.LittleEndian.PutUint32(result[0:4], a)
	binary.LittleEndian.PutUint32(result[4:8], b)
	binary.LittleEndian.PutUint32(result[8:12], c)
	binary.LittleEndian.PutUint32(result[12:16], d)

	return result, nil
}

// BlockSize returns the block size.
func (rc *RC6) BlockSize() int {
	return rc6BlockSize
}

func rotl32(x uint32, n int) uint32 {
	return bits.RotateLeft32(x, n)
}

func rotr32(x uint32, n int) uint32 {
	return bits.RotateLeft32(x, -n)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
