// Package des implements the DES encryption algorithm.
package des

import (
	"context"

	"github.com/masterkusok/crypto/bits"
	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/errors"
	"github.com/masterkusok/crypto/tables"
)

const (
	desBlockSize = 8
	desKeySize   = 8
	numRounds    = 16
)

// KeyScheduler implements DES key scheduling.
type KeyScheduler struct{}

// GenerateRoundKeys generates 16 round keys for DES.
func (k *KeyScheduler) GenerateRoundKeys(ctx context.Context, key []byte) ([][]byte, error) {
	if len(key) != desKeySize {
		return nil, errors.ErrInvalidKeySize
	}

	permuted, err := bits.Permute(key, tables.PC1, bits.MSBFirst, bits.StartFromOne)
	if err != nil {
		return nil, errors.Annotate(err, "PC1 permutation failed: %w")
	}

	c := make([]byte, 4)
	d := make([]byte, 4)
	copy(c, permuted[:4])
	copy(d, permuted[4:])

	roundKeys := make([][]byte, numRounds)
	for i := 0; i < numRounds; i++ {
		c = leftShift28(c, tables.KeyShifts[i])
		d = leftShift28(d, tables.KeyShifts[i])

		cd := append(append([]byte{}, c...), d...)
		roundKeys[i], err = bits.Permute(cd, tables.PC2, bits.MSBFirst, bits.StartFromOne)
		if err != nil {
			return nil, errors.Annotate(err, "PC2 permutation failed: %w")
		}
	}

	return roundKeys, nil
}

func leftShift28(data []byte, shifts int) []byte {
	result := make([]byte, len(data))
	copy(result, data)

	for s := 0; s < shifts; s++ {
		carry := (result[0] >> 7) & 1
		for i := 0; i < len(result)-1; i++ {
			result[i] = (result[i] << 1) | ((result[i+1] >> 7) & 1)
		}
		result[len(result)-1] = (result[len(result)-1] << 1) | carry
		result[len(result)-1] &= 0x0F
	}

	return result
}

// RoundFunction implements DES F function.
type RoundFunction struct{}

// Transform applies the DES F function.
func (r *RoundFunction) Transform(ctx context.Context, block, roundKey []byte) ([]byte, error) {
	expanded, err := bits.Permute(block, tables.ExpansionTable, bits.MSBFirst, bits.StartFromOne)
	if err != nil {
		return nil, errors.Annotate(err, "expansion failed: %w")
	}

	xored := make([]byte, len(expanded))
	for i := range expanded {
		xored[i] = expanded[i] ^ roundKey[i]
	}

	sboxOutput := make([]byte, 4)
	for i := 0; i < 8; i++ {
		sixBits := getSixBits(xored, i)
		row := ((sixBits >> 5) & 1) | ((sixBits & 1) << 1)
		col := (sixBits >> 1) & 0x0F
		val := tables.SBoxes[i][row*16+col]

		if i%2 == 0 {
			sboxOutput[i/2] |= val << 4
		} else {
			sboxOutput[i/2] |= val
		}
	}

	return bits.Permute(sboxOutput, tables.PPermutation, bits.MSBFirst, bits.StartFromOne)
}

func getSixBits(data []byte, index int) byte {
	bitPos := index * 6
	byteIdx := bitPos / 8
	bitOffset := bitPos % 8

	if bitOffset <= 2 {
		return (data[byteIdx] >> (2 - bitOffset)) & 0x3F
	}
	return ((data[byteIdx] << (bitOffset - 2)) | (data[byteIdx+1] >> (10 - bitOffset))) & 0x3F
}

// DES implements the DES cipher.
type DES struct {
	*cipher.FeistelNetwork
}

// NewDES creates a new DES cipher.
func NewDES() *DES {
	return &DES{
		FeistelNetwork: cipher.NewFeistelNetwork(&KeyScheduler{}, &RoundFunction{}, desBlockSize),
	}
}

// Encrypt encrypts a block with initial and final permutations.
func (d *DES) Encrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != desBlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	permuted, err := bits.Permute(block, tables.InitialPermutation, bits.MSBFirst, bits.StartFromOne)
	if err != nil {
		return nil, errors.Annotate(err, "initial permutation failed: %w")
	}

	encrypted, err := d.FeistelNetwork.Encrypt(ctx, permuted)
	if err != nil {
		return nil, err
	}

	return bits.Permute(encrypted, tables.FinalPermutation, bits.MSBFirst, bits.StartFromOne)
}

// Decrypt decrypts a block with initial and final permutations.
func (d *DES) Decrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != desBlockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	permuted, err := bits.Permute(block, tables.InitialPermutation, bits.MSBFirst, bits.StartFromOne)
	if err != nil {
		return nil, errors.Annotate(err, "initial permutation failed: %w")
	}

	decrypted, err := d.FeistelNetwork.Decrypt(ctx, permuted)
	if err != nil {
		return nil, err
	}

	return bits.Permute(decrypted, tables.FinalPermutation, bits.MSBFirst, bits.StartFromOne)
}
