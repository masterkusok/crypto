package cipher

import (
	"context"
	"io"
	"os"

	"github.com/masterkusok/crypto/errors"
)

type CipherContext struct {
	cipher  BlockCipher
	mode    CipherMode
	padding PaddingScheme
	iv      []byte
	params  map[string]interface{}
}

func NewCipherContext(cipher BlockCipher, key []byte, mode CipherMode, padding PaddingScheme, iv []byte, params ...interface{}) (*CipherContext, error) {
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

func (c *CipherContext) EncryptBytes(ctx context.Context, data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errChan)

		select {
		case <-ctx.Done():
			errChan <- ctx.Err()
			return
		default:
		}

		result, err := c.encryptSync(ctx, data)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- result
	}()

	return resultChan, errChan
}

func (c *CipherContext) DecryptBytes(ctx context.Context, data []byte) (<-chan []byte, <-chan error) {
	resultChan := make(chan []byte, 1)
	errChan := make(chan error, 1)

	go func() {
		defer close(resultChan)
		defer close(errChan)

		select {
		case <-ctx.Done():
			errChan <- ctx.Err()
			return
		default:
		}

		result, err := c.decryptSync(ctx, data)
		if err != nil {
			errChan <- err
			return
		}
		resultChan <- result
	}()

	return resultChan, errChan
}

func (c *CipherContext) encryptSync(ctx context.Context, data []byte) ([]byte, error) {
	padded, err := Pad(data, c.cipher.BlockSize(), c.padding)
	if err != nil {
		return nil, err
	}

	return c.mode.Encrypt(ctx, c.cipher, padded, c.iv)
}

func (c *CipherContext) decryptSync(ctx context.Context, data []byte) ([]byte, error) {
	decrypted, err := c.mode.Decrypt(ctx, c.cipher, data, c.iv)
	if err != nil {
		return nil, err
	}

	return Unpad(decrypted, c.padding)
}



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

func (c *CipherContext) EncryptStream(ctx context.Context, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.Annotate(err, "failed to read from stream: %w")
	}

	resultChan, errChan := c.EncryptBytes(ctx, data)
	select {
	case encrypted := <-resultChan:
		_, err = writer.Write(encrypted)
		return errors.Annotate(err, "failed to write to stream: %w")
	case err := <-errChan:
		return err
	}
}

func (c *CipherContext) DecryptStream(ctx context.Context, reader io.Reader, writer io.Writer) error {
	data, err := io.ReadAll(reader)
	if err != nil {
		return errors.Annotate(err, "failed to read from stream: %w")
	}

	resultChan, errChan := c.DecryptBytes(ctx, data)
	select {
	case decrypted := <-resultChan:
		_, err = writer.Write(decrypted)
		return errors.Annotate(err, "failed to write to stream: %w")
	case err := <-errChan:
		return err
	}
}


