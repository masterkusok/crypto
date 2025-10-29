package cipher

import (
	"fmt"
	"os"

	v "github.com/asaskevich/govalidator"
	"github.com/masterkusok/crypto/errors"
)

// ErrInvalidConfig is being returned if config passed to context constructor is
// invalid.
const ErrInvalidConfig = errors.ConstError("invalid config")

// Config is a configuration structure for [CipherContext].
type Config struct {
	// Algorithm is used for encrypyting/decrypting single text block
	Algorithm SymmetricAlgorithm `validate:"required"`

	// Mode is used for
	Mode Mode `validate:"required"`

	// Padding is used for padding blocks less then default block size.
	Padding Padding `validate:"required"`

	// BlockSize is a default block size.
	BlockSize int `validate:"required"`

	// IV is an initialization vector used for encrypying/decrypting.
	IV []byte

	// Counter is used in CTR Cipher mode.
	Counter []byte

	// SegmentSize is used in CFB Cipher mode.
	SegmentSize int

	// DeltaSize is used in RandomDelta Cipher mode.
	DeltaSize int
}

// CipherContext can encrypt and decrypt data using provided modes, algorithm,
// padding etc.
type CipherContext struct {
	algorithm SymmetricAlgorithm
	mode      Mode
	padding   Padding
	iv        []byte
	blockSize int

	counter     []byte
	segmentSize int
	deltaSize   int
}

// NewCipherContext creates new [CipherContext].  config must not be nil.
func NewCipherContext(config *Config) (*CipherContext, error) {
	ok, err := v.ValidateStruct(config)
	if err != nil {
		return nil, fmt.Errorf("initialize cipher context: %w", err)
	}

	if !ok {
		return nil, ErrInvalidConfig
	}

	if config.Mode.RequiresIV() && config.IV == nil {
		return nil, fmt.Errorf(
			"initialization vector is required for mode: %q",
			config.Mode.GetName())
	}

	return &CipherContext{
		algorithm:   config.Algorithm,
		mode:        config.Mode,
		padding:     config.Padding,
		iv:          config.IV,
		blockSize:   config.BlockSize,
		counter:     config.Counter,
		segmentSize: config.SegmentSize,
		deltaSize:   config.DeltaSize,
	}, nil
}

// EncryptAsync encrypts data async and writes to result.
func (c *CipherContext) EncryptAsync(data []byte, result *[]byte) <-chan error {
	ch := make(chan error, 1)

	go func() {
		defer close(ch)

		paddedData := c.padding.Pad(data, c.blockSize)

		blocks := c.splitIntoBlocks(paddedData, c.blockSize)

		encryptedBlocks := c.mode.Encrypt(blocks, c.algorithm, c.iv)

		*result = c.mergeBlocks(encryptedBlocks)
		ch <- nil
	}()

	return ch
}

// DecryptAsync decrypts data async and writes to result.
func (c *CipherContext) DecryptAsync(data []byte, result *[]byte) <-chan error {
	ch := make(chan error, 1)

	go func() {
		defer close(ch)

		blocks := c.splitIntoBlocks(data, c.blockSize)

		decryptedBlocks := c.mode.Decrypt(blocks, c.algorithm, c.iv)

		merged := c.mergeBlocks(decryptedBlocks)

		unpadded, err := c.padding.Unpad(merged, c.blockSize)
		if err != nil {
			ch <- err
			return
		}

		*result = unpadded
		ch <- nil
	}()

	return ch
}

// splitIntoBlocks returns slice of blocks of size blockSize from data.
func (c *CipherContext) splitIntoBlocks(data []byte, blockSize int) [][]byte {
	if blockSize <= 0 || len(data) == 0 {
		return [][]byte{}
	}

	blockCount := len(data) / blockSize
	blocks := make([][]byte, blockCount)

	for i := 0; i < blockCount; i++ {
		blocks[i] = data[i*blockSize : (i+1)*blockSize]
	}

	return blocks
}

// mergeBlocks merges slice of blocks into a single text.
func (c *CipherContext) mergeBlocks(blocks [][]byte) []byte {
	totalSize := 0
	for _, block := range blocks {
		totalSize += len(block)
	}

	result := make([]byte, totalSize)
	offset := 0

	for _, block := range blocks {
		copy(result[offset:], block)
		offset += len(block)
	}

	return result
}

func (c *CipherContext) EncryptFileAsync(inputPath, outputPath string) <-chan error {
	ch := make(chan error, 1)

	go func() {
		defer close(ch)
		ch <- c.processFile(inputPath, outputPath, true)
	}()

	return ch
}

func (c *CipherContext) DecryptFileAsync(inputPath, outputPath string) <-chan error {
	ch := make(chan error, 1)

	go func() {
		defer close(ch)
		ch <- c.processFile(inputPath, outputPath, false)
	}()

	return ch
}

func (c *CipherContext) processFile(inputPath, outputPath string, encrypt bool) error {
	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}

	var result []byte
	var resultCh <-chan error

	if encrypt {
		resultCh = c.EncryptAsync(inputData, &result)
	} else {
		resultCh = c.DecryptAsync(inputData, &result)
	}

	if err := <-resultCh; err != nil {
		return err
	}

	return os.WriteFile(outputPath, result, 0o644)
}
