package bits

import (
	"fmt"
)

// PBlock represents PBlock used for DES encryption.
type PBlock []int

// IsZeroIndexed returns if PBlock is already zero-indexed.
func (b PBlock) IsZeroIndexed() (ans bool) {
	for _, v := range b {
		if v == 0 {
			return true
		}
	}

	return false
}

// PermutateBits is a function, that applies P-Block bit permutation to byte
// slice.
//
// TODO(masterkusok): validate.
func PermutateBits(
	data []byte,
	pblock PBlock,
	indexingMode BitIndexMode,
	zeroIndexingAllowed bool,
) (permutated []byte, err error) {
	idxModifier := 0
	if zeroIndexingAllowed && !pblock.IsZeroIndexed() {
		idxModifier = -1
	}

	getter, setter, err := defaultBitIndexers(indexingMode)
	if err != nil {
		return nil, fmt.Errorf("obtaining default bit indexers: %w", err)
	}

	return permutateBits(data, pblock, idxModifier, getter, setter)
}

// permutate bits permutates bits in data according to p-block.
func permutateBits(
	data []byte,
	pblock PBlock,
	modifier int,
	getter bitGetter,
	setter bitSetter,
) (permutated []byte, err error) {
	n := len(pblock)
	permutated = make([]byte, MinBytes(n))
	for idx, pos := range pblock {
		if pos+modifier < 0 || pos+modifier >= len(data)*byteSize {
			return nil, fmt.Errorf("pblock out of range: at [%d]", idx)
		}

		value := getter(data, pos+modifier)
		setter(permutated, idx, value)
	}

	return permutated, nil
}
