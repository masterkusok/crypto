package cipher

import (
	"context"
	"sync"
)

type CipherMode interface {
	Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error)
	Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error)
}

type ECBMode struct{}

func (m *ECBMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
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
			encrypted, err := cipher.Encrypt(ctx, data[start:end])
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

func (m *ECBMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
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
			decrypted, err := cipher.Decrypt(ctx, data[start:end])
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

type CBCMode struct{}

func (m *CBCMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += blockSize {
		block := xorBlocks(data[i:i+blockSize], prev)
		encrypted, err := cipher.Encrypt(ctx, block)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], encrypted)
		prev = encrypted
	}

	return result, nil
}

func (m *CBCMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += blockSize {
		encrypted := data[i : i+blockSize]
		decrypted, err := cipher.Decrypt(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(decrypted, prev))
		prev = encrypted
	}

	return result, nil
}

type PCBCMode struct{}

func (m *PCBCMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += blockSize {
		plainBlock := data[i : i+blockSize]
		block := xorBlocks(plainBlock, prev)
		encrypted, err := cipher.Encrypt(ctx, block)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], encrypted)
		prev = xorBlocks(plainBlock, encrypted)
	}

	return result, nil
}

func (m *PCBCMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += blockSize {
		encrypted := data[i : i+blockSize]
		decrypted, err := cipher.Decrypt(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		plainBlock := xorBlocks(decrypted, prev)
		copy(result[i:i+blockSize], plainBlock)
		prev = xorBlocks(plainBlock, encrypted)
	}

	return result, nil
}

type CFBMode struct{}

func (m *CFBMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := cipher.Encrypt(ctx, prev)
		if err != nil {
			return nil, err
		}
		cipherBlock := xorBlocks(data[i:i+blockSize], encrypted)
		copy(result[i:i+blockSize], cipherBlock)
		prev = cipherBlock
	}

	return result, nil
}

func (m *CFBMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	prev := iv

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := cipher.Encrypt(ctx, prev)
		if err != nil {
			return nil, err
		}
		cipherBlock := data[i : i+blockSize]
		copy(result[i:i+blockSize], xorBlocks(cipherBlock, encrypted))
		prev = cipherBlock
	}

	return result, nil
}

type OFBMode struct{}

func (m *OFBMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	keystream := iv

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := cipher.Encrypt(ctx, keystream)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(data[i:i+blockSize], encrypted))
		keystream = encrypted
	}

	return result, nil
}

func (m *OFBMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	return m.Encrypt(ctx, cipher, data, iv)
}

type CTRMode struct{}

func (m *CTRMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	counter := make([]byte, blockSize)
	copy(counter, iv)

	for i := 0; i < len(data); i += blockSize {
		encrypted, err := cipher.Encrypt(ctx, counter)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(data[i:i+blockSize], encrypted))
		incrementCounter(counter)
	}

	return result, nil
}

func (m *CTRMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	return m.Encrypt(ctx, cipher, data, iv)
}

type RandomDeltaMode struct{}

func (m *RandomDeltaMode) Encrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	delta := iv

	for i := 0; i < len(data); i += blockSize {
		block := xorBlocks(data[i:i+blockSize], delta)
		encrypted, err := cipher.Encrypt(ctx, block)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], encrypted)
		delta = encrypted
	}

	return result, nil
}

func (m *RandomDeltaMode) Decrypt(ctx context.Context, cipher BlockCipher, data, iv []byte) ([]byte, error) {
	blockSize := cipher.BlockSize()
	result := make([]byte, len(data))
	delta := iv

	for i := 0; i < len(data); i += blockSize {
		encrypted := data[i : i+blockSize]
		decrypted, err := cipher.Decrypt(ctx, encrypted)
		if err != nil {
			return nil, err
		}
		copy(result[i:i+blockSize], xorBlocks(decrypted, delta))
		delta = encrypted
	}

	return result, nil
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
