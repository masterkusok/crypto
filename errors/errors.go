package errors

import "fmt"

type ConstError string

var _ error = (*ConstError)(nil)

func (e ConstError) Error() string {
	return string(e)
}

func Annotate(err error, format string, args ...any) (annotated error) {
	if err == nil {
		return err
	}

	return fmt.Errorf(format, append(args, err)...)
}

const (
	ErrInvalidKeySize       ConstError = "invalid key size"
	ErrInvalidBlockSize     ConstError = "invalid block size"
	ErrInvalidPTableSize    ConstError = "invalid permutation table size"
	ErrInvalidBitIndex      ConstError = "invalid bit index"
	ErrInvalidDataLength    ConstError = "invalid data length"
	ErrInvalidIVSize        ConstError = "invalid IV size"
	ErrInvalidPaddingScheme ConstError = "invalid padding scheme"
	ErrInvalidMode          ConstError = "invalid cipher mode"
	ErrInvalidParameters    ConstError = "invalid parameters"
	ErrInvalidPrivateKey    ConstError = "invalid private key"
	ErrInvalidPublicKey     ConstError = "invalid public key"
	ErrParameterMismatch    ConstError = "parameter mismatch"
)
