package cipher

import "github.com/masterkusok/crypto/errors"

type PaddingScheme int

const (
	Zeros PaddingScheme = iota
	ANSIX923
	PKCS7
	ISO10126
)

func Pad(data []byte, blockSize int, scheme PaddingScheme) ([]byte, error) {
	if blockSize <= 0 {
		return nil, errors.ErrInvalidBlockSize
	}

	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}

	padded := make([]byte, len(data)+padLen)
	copy(padded, data)

	switch scheme {
	case Zeros:
		// Already zeroed
	case ANSIX923:
		padded[len(padded)-1] = byte(padLen)
	case PKCS7:
		for i := len(data); i < len(padded); i++ {
			padded[i] = byte(padLen)
		}
	case ISO10126:
		padded[len(padded)-1] = byte(padLen)
	default:
		return nil, errors.ErrInvalidPaddingScheme
	}

	return padded, nil
}

func Unpad(data []byte, scheme PaddingScheme) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.ErrInvalidDataLength
	}

	switch scheme {
	case Zeros:
		i := len(data) - 1
		for i >= 0 && data[i] == 0 {
			i--
		}
		return data[:i+1], nil
	case ANSIX923, ISO10126:
		padLen := int(data[len(data)-1])
		if padLen > len(data) || padLen == 0 {
			return nil, errors.ErrInvalidDataLength
		}
		return data[:len(data)-padLen], nil
	case PKCS7:
		padLen := int(data[len(data)-1])
		if padLen > len(data) || padLen == 0 {
			return data, nil
		}
		for i := len(data) - padLen; i < len(data); i++ {
			if data[i] != byte(padLen) {
				return data, nil
			}
		}
		return data[:len(data)-padLen], nil
	default:
		return nil, errors.ErrInvalidPaddingScheme
	}
}
