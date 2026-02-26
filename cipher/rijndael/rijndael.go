package rijndael

import (
	"context"
	"sync"

	"github.com/masterkusok/crypto/errors"
	cryptoMath "github.com/masterkusok/crypto/math"
	"github.com/masterkusok/crypto/tables"
)

type Rijndael struct {
	blockSize int
	keySize   int
	numRounds int
	modulus   byte
	sbox      [256]byte
	invSbox   [256]byte
	roundKeys [][]byte
	sboxInit  sync.Once
}

func NewRijndael(blockSize, keySize int, modulus byte) (*Rijndael, error) {
	if blockSize != 16 && blockSize != 24 && blockSize != 32 {
		return nil, errors.ErrInvalidBlockSize
	}
	if keySize != 16 && keySize != 24 && keySize != 32 {
		return nil, errors.ErrInvalidKeySize
	}
	if !cryptoMath.IsIrreducible(modulus) {
		return nil, cryptoMath.ErrReduciblePolynomial
	}

	numRounds := calculateRounds(blockSize, keySize)

	return &Rijndael{
		blockSize: blockSize,
		keySize:   keySize,
		numRounds: numRounds,
		modulus:   modulus,
	}, nil
}

func calculateRounds(blockSize, keySize int) int {
	nb := blockSize / 4
	nk := keySize / 4
	if nb >= nk {
		return nb + 6
	}
	return nk + 6
}

func (r *Rijndael) SetKey(ctx context.Context, key []byte) error {
	if len(key) != r.keySize {
		return errors.ErrInvalidKeySize
	}

	r.initSBox()

	var err error
	r.roundKeys, err = r.keyExpansion(key)
	return err
}

func (r *Rijndael) Encrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != r.blockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	if r.roundKeys == nil {
		return nil, errors.ErrInvalidKeySize
	}

	state := make([]byte, len(block))
	copy(state, block)

	r.addRoundKey(state, r.roundKeys[0])

	for round := 1; round < r.numRounds; round++ {
		r.subBytes(state)
		r.shiftRows(state)
		r.mixColumns(state)
		r.addRoundKey(state, r.roundKeys[round])
	}

	r.subBytes(state)
	r.shiftRows(state)
	r.addRoundKey(state, r.roundKeys[r.numRounds])

	return state, nil
}

func (r *Rijndael) Decrypt(ctx context.Context, block []byte) ([]byte, error) {
	if len(block) != r.blockSize {
		return nil, errors.ErrInvalidBlockSize
	}

	if r.roundKeys == nil {
		return nil, errors.ErrInvalidKeySize
	}

	state := make([]byte, len(block))
	copy(state, block)

	r.addRoundKey(state, r.roundKeys[r.numRounds])
	r.invShiftRows(state)
	r.invSubBytes(state)

	for round := r.numRounds - 1; round > 0; round-- {
		r.addRoundKey(state, r.roundKeys[round])
		r.invMixColumns(state)
		r.invShiftRows(state)
		r.invSubBytes(state)
	}

	r.addRoundKey(state, r.roundKeys[0])

	return state, nil
}

func (r *Rijndael) BlockSize() int {
	return r.blockSize
}

func (r *Rijndael) initSBox() {
	r.sboxInit.Do(func() {
		for i := 0; i < 256; i++ {
			val := byte(i)
			if val == 0 {
				val = 0
			} else {
				val, _ = cryptoMath.GF256Inv(val, r.modulus)
			}

			val = r.affineTransform(val)
			r.sbox[i] = val
		}

		for i := 0; i < 256; i++ {
			r.invSbox[r.sbox[i]] = byte(i)
		}
	})
}

func (r *Rijndael) affineTransform(b byte) byte {
	result := byte(0)
	for i := 0; i < 8; i++ {
		bit := byte(0)
		bit ^= (b >> i) & 1
		bit ^= (b >> ((i + 4) % 8)) & 1
		bit ^= (b >> ((i + 5) % 8)) & 1
		bit ^= (b >> ((i + 6) % 8)) & 1
		bit ^= (b >> ((i + 7) % 8)) & 1
		result |= bit << i
	}
	return result ^ 0x63
}

func (r *Rijndael) subBytes(state []byte) {
	for i := range state {
		state[i] = r.sbox[state[i]]
	}
}

func (r *Rijndael) invSubBytes(state []byte) {
	for i := range state {
		state[i] = r.invSbox[state[i]]
	}
}

func (r *Rijndael) shiftRows(state []byte) {
	nb := r.blockSize / 4
	temp := make([]byte, r.blockSize)
	copy(temp, state)

	for row := 0; row < 4; row++ {
		for col := 0; col < nb; col++ {
			state[row+4*col] = temp[row+4*((col+row)%nb)]
		}
	}
}

func (r *Rijndael) invShiftRows(state []byte) {
	nb := r.blockSize / 4
	temp := make([]byte, r.blockSize)
	copy(temp, state)

	for row := 0; row < 4; row++ {
		for col := 0; col < nb; col++ {
			state[row+4*col] = temp[row+4*((col-row+nb)%nb)]
		}
	}
}

func (r *Rijndael) mixColumns(state []byte) {
	nb := r.blockSize / 4
	for col := 0; col < nb; col++ {
		r.mixColumn(state[col*4 : col*4+4])
	}
}

func (r *Rijndael) mixColumn(col []byte) {
	temp := make([]byte, 4)
	copy(temp, col)

	for i := 0; i < 4; i++ {
		col[i] = 0
		for j := 0; j < 4; j++ {
			t, _ := cryptoMath.GF256Mul(tables.RijndaelMixColumnMatrix[i][j], temp[j], r.modulus)
			col[i] = cryptoMath.GF256Add(col[i], t)
		}
	}
}

func (r *Rijndael) invMixColumns(state []byte) {
	nb := r.blockSize / 4
	for col := 0; col < nb; col++ {
		r.invMixColumn(state[col*4 : col*4+4])
	}
}

func (r *Rijndael) invMixColumn(col []byte) {
	temp := make([]byte, 4)
	copy(temp, col)

	for i := 0; i < 4; i++ {
		col[i] = 0
		for j := 0; j < 4; j++ {
			t, _ := cryptoMath.GF256Mul(tables.RijndaelInvMixColumnMatrix[i][j], temp[j], r.modulus)
			col[i] = cryptoMath.GF256Add(col[i], t)
		}
	}
}

func (r *Rijndael) addRoundKey(state, roundKey []byte) {
	for i := range state {
		state[i] ^= roundKey[i]
	}
}

func (r *Rijndael) keyExpansion(key []byte) ([][]byte, error) {
	nk := r.keySize / 4
	nb := r.blockSize / 4
	nr := r.numRounds

	w := make([][]byte, nb*(nr+1))
	for i := range w {
		w[i] = make([]byte, 4)
	}

	for i := 0; i < nk; i++ {
		copy(w[i], key[4*i:4*i+4])
	}

	for i := nk; i < nb*(nr+1); i++ {
		temp := make([]byte, 4)
		copy(temp, w[i-1])

		if i%nk == 0 {
			temp = r.rotWord(temp)
			temp = r.subWord(temp)
			temp[0] ^= r.rcon(i / nk)
		} else if nk > 6 && i%nk == 4 {
			temp = r.subWord(temp)
		}

		for j := 0; j < 4; j++ {
			w[i][j] = w[i-nk][j] ^ temp[j]
		}
	}

	roundKeys := make([][]byte, nr+1)
	for i := 0; i <= nr; i++ {
		roundKeys[i] = make([]byte, r.blockSize)
		for j := 0; j < nb; j++ {
			copy(roundKeys[i][j*4:j*4+4], w[i*nb+j])
		}
	}

	return roundKeys, nil
}

func (r *Rijndael) rotWord(word []byte) []byte {
	return []byte{word[1], word[2], word[3], word[0]}
}

func (r *Rijndael) subWord(word []byte) []byte {
	result := make([]byte, 4)
	for i := range word {
		result[i] = r.sbox[word[i]]
	}
	return result
}

func (r *Rijndael) rcon(i int) byte {
	rc := byte(1)
	for j := 1; j < i; j++ {
		rc, _ = cryptoMath.GF256Mul(rc, 0x02, r.modulus)
	}
	return rc
}
