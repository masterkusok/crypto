// Package rsa implements RSA encryption algorithm with key generation and Wiener attack.
package rsa

import (
	"context"
	"crypto/rand"
	"io"
	"math/big"
	"os"
	"sync"

	"github.com/masterkusok/crypto/errors"
)

// PublicKey represents RSA public key.
type PublicKey struct {
	N *big.Int // modulus
	E *big.Int // public exponent
}

// PrivateKey represents RSA private key.
type PrivateKey struct {
	PublicKey
	D *big.Int // private exponent
	P *big.Int // prime factor
	Q *big.Int // prime factor
}

// GenerateKey generates RSA key pair with protection against Wiener attack.
// For Wiener attack protection: d > N^(1/4)
func GenerateKey(bits int) (*PrivateKey, error) {
	if bits < 512 {
		return nil, errors.ErrInvalidKeySize
	}

	for {
		p, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, errors.Annotate(err, "failed to generate prime p: %w")
		}

		q, err := rand.Prime(rand.Reader, bits/2)
		if err != nil {
			return nil, errors.Annotate(err, "failed to generate prime q: %w")
		}

		if p.Cmp(q) == 0 {
			continue
		}

		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(q, big.NewInt(1)),
		)

		e := big.NewInt(65537)
		if new(big.Int).GCD(nil, nil, e, phi).Cmp(big.NewInt(1)) != 0 {
			continue
		}

		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}

		// Wiener attack protection: d > N^(1/4)
		nSqrt := new(big.Int).Sqrt(n)
		nFourthRoot := new(big.Int).Sqrt(nSqrt)
		if d.Cmp(nFourthRoot) <= 0 {
			continue
		}

		return &PrivateKey{
			PublicKey: PublicKey{N: n, E: e},
			D:         d,
			P:         p,
			Q:         q,
		}, nil
	}
}

// Encrypt encrypts message with public key.
func (pub *PublicKey) Encrypt(message []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(message)
	if m.Cmp(pub.N) >= 0 {
		return nil, errors.ErrMessageTooLarge
	}

	c := new(big.Int).Exp(m, pub.E, pub.N)
	return c.Bytes(), nil
}

// Decrypt decrypts ciphertext with private key.
func (priv *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	c := new(big.Int).SetBytes(ciphertext)
	if c.Cmp(priv.N) >= 0 {
		return nil, errors.ErrInvalidDataLength
	}

	m := new(big.Int).Exp(c, priv.D, priv.N)
	return m.Bytes(), nil
}

// RSA provides high-level RSA operations.
type RSA struct {
	privateKey *PrivateKey
	publicKey  *PublicKey
}

// NewRSA creates RSA instance with generated keys.
func NewRSA(bits int) (*RSA, error) {
	priv, err := GenerateKey(bits)
	if err != nil {
		return nil, err
	}

	return &RSA{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
	}, nil
}

// NewRSAWithKeys creates RSA instance with existing keys.
func NewRSAWithKeys(priv *PrivateKey) *RSA {
	return &RSA{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
	}
}

// PublicKey returns public key.
func (r *RSA) PublicKey() *PublicKey {
	return r.publicKey
}

// PrivateKey returns private key.
func (r *RSA) PrivateKey() *PrivateKey {
	return r.privateKey
}

// EncryptBytes encrypts data asynchronously.
func (r *RSA) EncryptBytes(ctx context.Context, data []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		blockSize := (r.publicKey.N.BitLen() - 1) / 8
		if blockSize <= 0 {
			errChan <- errors.ErrInvalidBlockSize
			return
		}

		var result []byte
		for i := 0; i < len(data); i += blockSize {
			end := i + blockSize
			if end > len(data) {
				end = len(data)
			}

			block := data[i:end]
			// Pad block to blockSize with zeros
			paddedBlock := make([]byte, blockSize)
			copy(paddedBlock, block)

			encrypted, err := r.publicKey.Encrypt(paddedBlock)
			if err != nil {
				errChan <- err
				return
			}

			// Pad to fixed size
			encBlock := make([]byte, (r.publicKey.N.BitLen()+7)/8)
			copy(encBlock[len(encBlock)-len(encrypted):], encrypted)
			result = append(result, encBlock...)
		}

		resultChan <- result
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, err
	case result := <-resultChan:
		return result, nil
	}
}

// DecryptBytes decrypts data asynchronously.
func (r *RSA) DecryptBytes(ctx context.Context, data []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		blockSize := (r.privateKey.N.BitLen() + 7) / 8
		plainBlockSize := (r.privateKey.N.BitLen() - 1) / 8
		if len(data)%blockSize != 0 {
			errChan <- errors.ErrInvalidDataLength
			return
		}

		var result []byte
		for i := 0; i < len(data); i += blockSize {
			block := data[i : i+blockSize]
			decrypted, err := r.privateKey.Decrypt(block)
			if err != nil {
				errChan <- err
				return
			}
			// Pad to original block size to preserve structure
			paddedBlock := make([]byte, plainBlockSize)
			copy(paddedBlock[plainBlockSize-len(decrypted):], decrypted)
			result = append(result, paddedBlock...)
		}

		// Remove trailing zeros from last block
		for len(result) > 0 && result[len(result)-1] == 0 {
			result = result[:len(result)-1]
		}

		resultChan <- result
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, err
	case result := <-resultChan:
		return result, nil
	}
}

// EncryptFile encrypts file asynchronously and in parallel.
func (r *RSA) EncryptFile(ctx context.Context, inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return errors.Annotate(err, "failed to read input file: %w")
	}

	blockSize := (r.publicKey.N.BitLen() - 1) / 8
	numBlocks := (len(data) + blockSize - 1) / blockSize

	encryptedBlocks := make([][]byte, numBlocks)
	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			start := idx * blockSize
			end := start + blockSize
			if end > len(data) {
				end = len(data)
			}

			encrypted, err := r.publicKey.Encrypt(data[start:end])
			if err != nil {
				errChan <- err
				return
			}

			encBlock := make([]byte, (r.publicKey.N.BitLen()+7)/8)
			copy(encBlock[len(encBlock)-len(encrypted):], encrypted)
			encryptedBlocks[idx] = encBlock
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return err
	}

	var result []byte
	for _, block := range encryptedBlocks {
		result = append(result, block...)
	}

	return os.WriteFile(outputPath, result, 0644)
}

// DecryptFile decrypts file asynchronously and in parallel.
func (r *RSA) DecryptFile(ctx context.Context, inputPath, outputPath string) error {
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return errors.Annotate(err, "failed to read input file: %w")
	}

	blockSize := (r.privateKey.N.BitLen() + 7) / 8
	if len(data)%blockSize != 0 {
		return errors.ErrInvalidDataLength
	}

	numBlocks := len(data) / blockSize
	decryptedBlocks := make([][]byte, numBlocks)
	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			start := idx * blockSize
			block := data[start : start+blockSize]

			decrypted, err := r.privateKey.Decrypt(block)
			if err != nil {
				errChan <- err
				return
			}

			decryptedBlocks[idx] = decrypted
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return err
	}

	var result []byte
	for _, block := range decryptedBlocks {
		result = append(result, block...)
	}

	return os.WriteFile(outputPath, result, 0644)
}

// EncryptStream encrypts data from reader to writer.
func (r *RSA) EncryptStream(ctx context.Context, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.Annotate(err, "failed to read from stream: %w")
	}

	encrypted, err := r.EncryptBytes(ctx, data)
	if err != nil {
		return err
	}

	_, err = writer.Write(encrypted)
	return errors.Annotate(err, "failed to write to stream: %w")
}

// DecryptStream decrypts data from reader to writer.
func (r *RSA) DecryptStream(ctx context.Context, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.Annotate(err, "failed to read from stream: %w")
	}

	decrypted, err := r.DecryptBytes(ctx, data)
	if err != nil {
		return err
	}

	_, err = writer.Write(decrypted)
	return errors.Annotate(err, "failed to write to stream: %w")
}
