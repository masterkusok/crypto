package cipher

import (
	"crypto/rand"
	"errors"
)

// Padding is and interface for entities implementing different block padding
// strategies.
type Padding interface {
	Pad(data []byte, blockSize int) []byte
	Unpad(data []byte, blockSize int) ([]byte, error)
	GetName() string
}

type ZerosPadding struct{}

var _ (Padding) = (*ZerosPadding)(nil)

func (z *ZerosPadding) Pad(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	if paddingSize == 0 {
		paddingSize = blockSize
	}

	padded := make([]byte, len(data)+paddingSize)
	copy(padded, data)

	return padded
}

func (z *ZerosPadding) Unpad(data []byte, blockSize int) ([]byte, error) {
	i := len(data) - 1
	for i >= 0 && data[i] == 0 {
		i--
	}

	return data[:i+1], nil
}

func (z *ZerosPadding) GetName() string { return "Zeros" }

type ANSIX923Padding struct{}

var _ (Padding) = (*ANSIX923Padding)(nil)

func (a *ANSIX923Padding) Pad(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	if paddingSize == 0 {
		paddingSize = blockSize
	}

	padded := make([]byte, len(data)+paddingSize)
	copy(padded, data)
	padded[len(padded)-1] = byte(paddingSize)

	return padded
}

func (a *ANSIX923Padding) Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	paddingSize := int(data[len(data)-1])
	if paddingSize > len(data) || paddingSize > blockSize {
		return nil, errors.New("invalid padding")
	}

	for i := len(data) - paddingSize; i < len(data)-1; i++ {
		if data[i] != 0 {
			return nil, errors.New("invalid ANSI X.923 padding")
		}
	}

	return data[:len(data)-paddingSize], nil
}

func (a *ANSIX923Padding) GetName() string { return "ANSI X.923" }

type PKCS7Padding struct{}

var _ (Padding) = (*PKCS7Padding)(nil)

func (p *PKCS7Padding) Pad(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	if paddingSize == 0 {
		paddingSize = blockSize
	}

	padded := make([]byte, len(data)+paddingSize)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(paddingSize)
	}

	return padded
}

func (p *PKCS7Padding) Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	paddingSize := int(data[len(data)-1])
	if paddingSize > len(data) || paddingSize > blockSize {
		return nil, errors.New("invalid padding")
	}

	for i := len(data) - paddingSize; i < len(data); i++ {
		if data[i] != byte(paddingSize) {
			return nil, errors.New("invalid PKCS7 padding")
		}
	}

	return data[:len(data)-paddingSize], nil
}

func (p *PKCS7Padding) GetName() string { return "PKCS7" }

type ISO10126Padding struct{}

var _ (Padding) = (*ISO10126Padding)(nil)

func (i *ISO10126Padding) Pad(data []byte, blockSize int) []byte {
	paddingSize := blockSize - len(data)%blockSize
	if paddingSize == 0 {
		paddingSize = blockSize
	}

	padded := make([]byte, len(data)+paddingSize)
	copy(padded, data)

	randBytes := make([]byte, paddingSize-1)
	_, err := rand.Read(randBytes)
	if err != nil {
		panic(err)
	}

	copy(padded[len(data):len(data)+paddingSize-1], randBytes)

	padded[len(padded)-1] = byte(paddingSize)

	return padded
}

func (i *ISO10126Padding) Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}
	paddingSize := int(data[len(data)-1])
	if paddingSize > len(data) || paddingSize > blockSize {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-paddingSize], nil
}

func (i *ISO10126Padding) GetName() string { return "ISO 10126" }
