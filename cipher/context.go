package cipher

import (
	"context"
	"io"
	"os"
	"sync"

	"github.com/masterkusok/crypto/errors"
)

// CipherContext provides encryption/decryption with modes and padding.
type CipherContext struct {
	cipher  BlockCipher
	mode    Mode
	padding PaddingScheme
	iv      []byte
	params  map[string]interface{}
}

// NewCipherContext creates a new cipher context.
func NewCipherContext(cipher BlockCipher, key []byte, mode Mode, padding PaddingScheme, iv []byte, params ...interface{}) (*CipherContext, error) {
	ctx := context.Background()
	if err := cipher.SetKey(ctx, key); err != nil {
		return nil, errors.Annotate(err, "failed to set key: %w")
	}

	if iv != nil && len(iv) != cipher.BlockSize() {
		return nil, errors.ErrInvalidIVSize
	}

	paramsMap := make(map[string]interface{})
	for i := 0; i < len(params); i += 2 {
		if i+1 < len(params) {
			if key, ok := params[i].(string); ok {
				paramsMap[key] = params[i+1]
			}
		}
	}

	return &CipherContext{
		cipher:  cipher,
		mode:    mode,
		padding: padding,
		iv:      iv,
		params:  paramsMap,
	}, nil
}

// EncryptBytes encrypts data asynchronously.
func (c *CipherContext) EncryptBytes(ctx context.Context, data []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := c.encryptSync(ctx, data)
		if err != nil {
			errChan <- err
			return
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
func (c *CipherContext) DecryptBytes(ctx context.Context, data []byte) ([]byte, error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		result, err := c.decryptSync(ctx, data)
		if err != nil {
			errChan <- err
			return
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

func (c *CipherContext) encryptSync(ctx context.Context, data []byte) ([]byte, error) {
	padded, err := Pad(data, c.cipher.BlockSize(), c.padding)
	if err != nil {
		return nil, err
	}

	switch c.mode {
	case ECB:
		return c.encryptECB(ctx, padded)
	case CBC:
		return c.encryptCBC(ctx, padded)
	case PCBC:
		return c.encryptPCBC(ctx, padded)
	case CFB:
		return c.encryptCFB(ctx, padded)
	case OFB:
		return c.encryptOFB(ctx, padded)
	case CTR:
		return c.encryptCTR(ctx, padded)
	case RandomDelta:
		return c.encryptRandomDelta(ctx, padded)
	default:
		return nil, errors.ErrInvalidMode
	}
}

func (c *CipherContext) decryptSync(ctx context.Context, data []byte) ([]byte, error) {
	var decrypted []byte
	var err error

	switch c.mode {
	case ECB:
		decrypted, err = c.decryptECB(ctx, data)
	case CBC:
		decrypted, err = c.decryptCBC(ctx, data)
	case PCBC:
		decrypted, err = c.decryptPCBC(ctx, data)
	case CFB:
		decrypted, err = c.decryptCFB(ctx, data)
	case OFB:
		decrypted, err = c.decryptOFB(ctx, data)
	case CTR:
		decrypted, err = c.decryptCTR(ctx, data)
	case RandomDelta:
		decrypted, err = c.decryptRandomDelta(ctx, data)
	default:
		return nil, errors.ErrInvalidMode
	}

	if err != nil {
		return nil, err
	}

	return Unpad(decrypted, c.padding)
}

func (c *CipherContext) encryptECB(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize

	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := idx * blockSize
			end := start + blockSize
			encrypted, err := c.cipher.Encrypt(ctx, data[start:end])
			if err != nil {
				errChan <- err
				return
			}
			copy(result[start:end], encrypted)
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return result, nil
}

func (c *CipherContext) decryptECB(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	numBlocks := len(data) / blockSize

	var wg sync.WaitGroup
	errChan := make(chan error, numBlocks)

	for i := 0; i < numBlocks; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			start := idx * blockSize
			end := start + blockSize
			decrypted, err := c.cipher.Decrypt(ctx, data[start:end])
			if err != nil {
				errChan <- err
				return
			}
			copy(result[start:end], decrypted)
		}(i)
	}

	wg.Wait()
	close(errChan)

	if err := <-errChan; err != nil {
		return nil, err
	}

	return result, nil
}

func (c *CipherContext) encryptCBC(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	prev := c.iv

	for i := 0; i < len(data); i += blockSize {
		block := xorBlocks(data[i:i+blockSize], prev)
		encrypted, err := c.cipher.Encrypt(ctx, block)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], encrypted)
		prev = encrypted
	}

	return result, nil
}

func (c *CipherContext) decryptCBC(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	prev := c.iv

	for i := 0; i < len(data); i += blockSize {
		encrypted := data[i : i+blockSize]
		decrypted, err := c.cipher.Decrypt(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(decrypted, prev))
		prev = encrypted
	}

	return result, nil
}

func (c *CipherContext) encryptPCBC(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	prev := c.iv

	for i := 0; i < len(data); i += blockSize {
		plainBlock := data[i : i+blockSize]
		block := xorBlocks(plainBlock, prev)
		encrypted, err := c.cipher.Encrypt(ctx, block)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], encrypted)
		prev = xorBlocks(plainBlock, encrypted)
	}

	return result, nil
}

func (c *CipherContext) decryptPCBC(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	prev := c.iv

	for i := 0; i < len(data); i += blockSize {
		encrypted := data[i : i+blockSize]
		decrypted, err := c.cipher.Decrypt(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		plainBlock := xorBlocks(decrypted, prev)
		copy(result[i:i+blockSize], plainBlock)
		prev = xorBlocks(plainBlock, encrypted)
	}

	return result, nil
}

func (c *CipherContext) encryptCFB(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	prev := c.iv

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := c.cipher.Encrypt(ctx, prev)
		if err != nil {
			return nil, err
		}
		cipherBlock := xorBlocks(data[i:i+blockSize], encrypted)
		copy(result[i:i+blockSize], cipherBlock)
		prev = cipherBlock
	}

	return result, nil
}

func (c *CipherContext) decryptCFB(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	prev := c.iv

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := c.cipher.Encrypt(ctx, prev)
		if err != nil {
			return nil, err
		}
		cipherBlock := data[i : i+blockSize]
		copy(result[i:i+blockSize], xorBlocks(cipherBlock, encrypted))
		prev = cipherBlock
	}

	return result, nil
}

func (c *CipherContext) encryptOFB(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	keystream := c.iv

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := c.cipher.Encrypt(ctx, keystream)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(data[i:i+blockSize], encrypted))
		keystream = encrypted
	}

	return result, nil
}

func (c *CipherContext) decryptOFB(ctx context.Context, data []byte) ([]byte, error) {
	return c.encryptOFB(ctx, data)
}

func (c *CipherContext) encryptCTR(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	counter := make([]byte, blockSize)
	copy(counter, c.iv)

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := c.cipher.Encrypt(ctx, counter)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(data[i:i+blockSize], encrypted))
		incrementCounter(counter)
	}

	return result, nil
}

func (c *CipherContext) decryptCTR(ctx context.Context, data []byte) ([]byte, error) {
	return c.encryptCTR(ctx, data)
}

func (c *CipherContext) encryptRandomDelta(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	delta := c.iv

	for i := 0; i < len(data); i += blockSize {
		block := xorBlocks(data[i:i+blockSize], delta)
		encrypted, err := c.cipher.Encrypt(ctx, block)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], encrypted)
		delta = encrypted
	}

	return result, nil
}

func (c *CipherContext) decryptRandomDelta(ctx context.Context, data []byte) ([]byte, error) {
	blockSize := c.cipher.BlockSize()
	result := make([]byte, len(data))
	delta := c.iv

	for i := 0; i < len(data); i += blockSize {
		encrypted := data[i : i+blockSize]
		decrypted, err := c.cipher.Decrypt(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(decrypted, delta))
		delta = encrypted
	}

	return result, nil
}

// EncryptFile encrypts a file asynchronously.
func (c *CipherContext) EncryptFile(ctx context.Context, inputPath, outputPath string) error {
	errChan := make(chan error, 1)

	go func() {
		data, err := os.ReadFile(inputPath)
		if err != nil {
			errChan <- errors.Annotate(err, "failed to read input file: %w")
			return
		}

		encrypted, err := c.encryptSync(ctx, data)
		if err != nil {
			errChan <- err
			return
		}

		if err := os.WriteFile(outputPath, encrypted, 0644); err != nil {
			errChan <- errors.Annotate(err, "failed to write output file: %w")
			return
		}

		errChan <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

// DecryptFile decrypts a file asynchronously.
func (c *CipherContext) DecryptFile(ctx context.Context, inputPath, outputPath string) error {
	errChan := make(chan error, 1)

	go func() {
		data, err := os.ReadFile(inputPath)
		if err != nil {
			errChan <- errors.Annotate(err, "failed to read input file: %w")
			return
		}

		decrypted, err := c.decryptSync(ctx, data)
		if err != nil {
			errChan <- err
			return
		}

		if err := os.WriteFile(outputPath, decrypted, 0644); err != nil {
			errChan <- errors.Annotate(err, "failed to write output file: %w")
			return
		}

		errChan <- nil
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errChan:
		return err
	}
}

// EncryptStream encrypts data from reader to writer.
func (c *CipherContext) EncryptStream(ctx context.Context, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.Annotate(err, "failed to read from stream: %w")
	}

	encrypted, err := c.EncryptBytes(ctx, data)
	if err != nil {
		return err
	}

	_, err = writer.Write(encrypted)
	return errors.Annotate(err, "failed to write to stream: %w")
}

// DecryptStream decrypts data from reader to writer.
func (c *CipherContext) DecryptStream(ctx context.Context, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.Annotate(err, "failed to read from stream: %w")
	}

	decrypted, err := c.DecryptBytes(ctx, data)
	if err != nil {
		return err
	}

	_, err = writer.Write(decrypted)
	return errors.Annotate(err, "failed to write to stream: %w")
}

func xorBlocks(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}
