package bits_test

import (
	"testing"

	"github.com/masterkusok/crypto/bits"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermutateBits(t *testing.T) {
	testCases := []struct {
		name         string
		data         []byte
		pblock       bits.PBlock
		mode         bits.BitIndexMode
		zeroIndexing bool
		want         []byte
		wantErr      require.ErrorAssertionFunc
	}{
		{
			name:         "simple_reverse_MSB",
			data:         []byte{0b11001010},
			pblock:       bits.PBlock{7, 6, 5, 4, 3, 2, 1, 0},
			mode:         bits.Inverted,
			zeroIndexing: true,
			want:         []byte{0b01010011},
			wantErr:      require.NoError,
		},
		{
			name:         "simple_reverse_LSB",
			data:         []byte{0b11001010},
			pblock:       bits.PBlock{7, 6, 5, 4, 3, 2, 1, 0},
			mode:         bits.Normal,
			zeroIndexing: true,
			want:         []byte{0b01010011},
			wantErr:      require.NoError,
		},
		{
			name:         "identity_mapping",
			data:         []byte{0b10101010},
			pblock:       bits.PBlock{0, 1, 2, 3, 4, 5, 6, 7},
			mode:         bits.Inverted,
			zeroIndexing: true,
			want:         []byte{0b10101010},
			wantErr:      require.NoError,
		},
		{
			name:         "two_bytes_permutation",
			data:         []byte{0b11110000, 0b00001111},
			pblock:       bits.PBlock{15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
			mode:         bits.Inverted,
			zeroIndexing: true,
			want:         []byte{0b11110000, 0b00001111},
			wantErr:      require.NoError,
		},
		{
			name:         "out_of_range_should_fail",
			data:         []byte{0b00001111},
			pblock:       bits.PBlock{8, 9, 10},
			mode:         bits.Inverted,
			zeroIndexing: true,
			wantErr:      require.Error,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := bits.PermutateBits(tc.data, tc.pblock, tc.mode, tc.zeroIndexing)
			tc.wantErr(t, err)

			assert.Equal(t, tc.want, got)
		})
	}
}
