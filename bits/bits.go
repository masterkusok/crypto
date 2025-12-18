// Package bits contains common functions for working with bits.
package bits

import "github.com/masterkusok/crypto/errors"

// byteSize is a number of bits that fit in one Byte.
const byteSize = 8

// IndexingRule defines how bits are indexed in a byte.
type IndexingRule int

const (
	// LSBFirst indexes bits from least significant to most significant (0 is rightmost).
	LSBFirst IndexingRule = iota
	// MSBFirst indexes bits from most significant to least significant (0 is leftmost).
	MSBFirst
)

// StartBit defines the starting index for bit numbering.
type StartBit int

const (
	// StartFromZero means bit indexing starts at 0.
	StartFromZero StartBit = iota
	// StartFromOne means bit indexing starts at 1.
	StartFromOne
)

// Permute performs bit permutation on data according to pTable.
// pTable contains bit positions (adjusted by startBit).
// indexRule defines bit indexing order.
func Permute(data []byte, pTable []int, indexRule IndexingRule, startBit StartBit) ([]byte, error) {
	if len(pTable) == 0 {
		return nil, errors.ErrInvalidPTableSize
	}

	totalBits := len(data) * byteSize
	outputBits := len(pTable)
	output := make([]byte, (outputBits+7)/8)

	for i, pos := range pTable {
		if startBit == StartFromOne {
			pos--
		}
		if pos < 0 || pos >= totalBits {
			return nil, errors.ErrInvalidBitIndex
		}

		bit := getBit(data, pos, indexRule)
		setBit(output, i, bit, indexRule)
	}

	return output, nil
}

func getBit(data []byte, pos int, rule IndexingRule) byte {
	byteIdx := pos / byteSize
	bitIdx := pos % byteSize

	if rule == MSBFirst {
		bitIdx = byteSize - 1 - bitIdx
	}

	return (data[byteIdx] >> bitIdx) & 1
}

func setBit(data []byte, pos int, value byte, rule IndexingRule) {
	byteIdx := pos / byteSize
	bitIdx := pos % byteSize

	if rule == MSBFirst {
		bitIdx = byteSize - 1 - bitIdx
	}

	if value&1 == 1 {
		data[byteIdx] |= 1 << bitIdx
	} else {
		data[byteIdx] &^= 1 << bitIdx
	}
}
