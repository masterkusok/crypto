// Package bits contains common functions for working with bits.
package bits

import "errors"

// byteSize is a number of bits that fit in one Byte.
const byteSize = 8

// BitIndexMode represents different modes for indexing bits inside of one byte.
type BitIndexMode int8

const (
	// Normal is a BitIndexMode witch index bits from LSB to MSB.
	Normal BitIndexMode = 0

	// Inverted means that bits are indexed from MSB to LSB.
	Inverted BitIndexMode = 1
)

// defaultBitIndexers returns default [bit.Getter] and [bit.Setter] for
// specified indexing mode.
func defaultBitIndexers(mode BitIndexMode) (getter bitGetter, setter bitSetter, err error) {
	switch mode {
	case Normal:
		return getBitNormal, setBitNormal, nil
	case Inverted:
		return getBitInverted, setBitInverted, nil
	default:
		return nil, nil, errors.New("invalid bit index mode")
	}
}

// MinBytes is a function that returns min number of bytes to fit in n bits.
func MinBytes(n int) (minLen int) {
	return (n + 7) / byteSize
}

// bigGetter is callback function for getting bit from bytes slice by its idx.
type bitGetter func(data []byte, idx int) (result byte)

// getBitNormal is a function that returns bit with specific index from byte
// slice for normal indexing mode.  data must not be nil, idx must be less than
// len(data) * 8.
func getBitNormal(data []byte, idx int) (result byte) {
	byteIdx := idx / byteSize
	bitIdx := idx % byteSize
	return (data[byteIdx] >> bitIdx) & 1
}

// getBitInverted is a function that returns bit with specific index from byte
// slice for inverted indexing mode.  data must not be nil, idx must be less
// than len(data) * 8.
func getBitInverted(data []byte, idx int) (result byte) {
	byteIndex := idx / byteSize
	bitIndex := 7 - (idx % byteSize)
	return (data[byteIndex] >> bitIndex) & 1
}

// bigSetter is callback function for setting bit in bytes slice by its idx.
type bitSetter func(data []byte, idx int, value byte)

// setBitNormal is a function that sets value for bit with specific index inside
// byte  slice for normal indexing mode.  data must not be nil, idx must be less
// than len(data) * 8.
func setBitNormal(data []byte, idx int, value byte) {
	byteIndex := idx / byteSize
	bitIndex := idx % byteSize
	if value == 1 {
		data[byteIndex] |= (1 << bitIndex)
	} else {
		data[byteIndex] &^= (1 << bitIndex)
	}
}

// setBitInverted is a function that sets value for bit with specific index
// inside byte slice for inverted indexing mode.  data must not be nil, idx
// must be less than len(data) * 8.
func setBitInverted(data []byte, idx int, value byte) {
	byteIndex := idx / byteSize
	bitIndex := 7 - (idx % 8)
	if value == 1 {
		data[byteIndex] |= (1 << bitIndex)
	} else {
		data[byteIndex] &^= (1 << bitIndex)
	}
}
