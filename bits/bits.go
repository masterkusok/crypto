package bits

import "github.com/masterkusok/crypto/errors"

const byteSize = 8

type IndexingRule int

const (
	LSBFirst IndexingRule = iota
	MSBFirst
)

type StartBit int

const (
	StartFromZero StartBit = iota
	StartFromOne
)

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
