package cipher

import "crypto/rand"

// Mode is an interface for cipher modes (such as ECB, CBC, PCBC etc).
type Mode interface {
	Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte
	Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte
	RequiresIV() bool
	GetName() string
}

// ECBMode represents.
type ECBMode struct{}

// type check
var _ Mode = (*ECBMode)(nil)

func (e *ECBMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	for i, block := range blocks {
		result[i] = algorithm.Encrypt(block)
	}
	return result
}

func (e *ECBMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	for i, block := range blocks {
		result[i] = algorithm.Decrypt(block)
	}
	return result
}

func (e *ECBMode) RequiresIV() bool { return false }
func (e *ECBMode) GetName() string  { return "ECB" }

// CBCMode .
type CBCMode struct{}

// type check
var _ Mode = (*CBCMode)(nil)

func (c *CBCMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for i, block := range blocks {
		xored := xorBytes(block, prev)
		encrypted := algorithm.Encrypt(xored)
		result[i] = encrypted
		prev = encrypted
	}
	return result
}

func (c *CBCMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for i, block := range blocks {
		decrypted := algorithm.Decrypt(block)
		result[i] = xorBytes(decrypted, prev)
		prev = block
	}
	return result
}

func (c *CBCMode) RequiresIV() bool { return true }
func (c *CBCMode) GetName() string  { return "CBC" }

type CFBMode struct{}

// type check
var _ Mode = (*CFBMode)(nil)

func (c *CFBMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	feedback := make([]byte, len(iv))
	copy(feedback, iv)

	for i, block := range blocks {
		encrypted := algorithm.Encrypt(feedback)
		result[i] = xorBytes(block, encrypted)
		feedback = result[i]
	}
	return result
}

func (c *CFBMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	feedback := make([]byte, len(iv))
	copy(feedback, iv)

	for i, block := range blocks {
		encrypted := algorithm.Encrypt(feedback)
		result[i] = xorBytes(block, encrypted)
		feedback = block
	}
	return result
}

func (c *CFBMode) RequiresIV() bool { return true }
func (c *CFBMode) GetName() string  { return "CFB" }

type OFBMode struct{}

// type check
var _ Mode = (*OFBMode)(nil)

func (o *OFBMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	return o.process(blocks, algorithm, iv)
}

func (o *OFBMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	return o.process(blocks, algorithm, iv)
}

func (o *OFBMode) process(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	feedback := make([]byte, len(iv))
	copy(feedback, iv)

	for i, block := range blocks {
		encrypted := algorithm.Encrypt(feedback)
		result[i] = xorBytes(block, encrypted)
		feedback = encrypted
	}
	return result
}

func (o *OFBMode) RequiresIV() bool { return true }
func (o *OFBMode) GetName() string  { return "OFB" }

type CTRMode struct {
	counter []byte
}

// type check
var _ Mode = (*CTRMode)(nil)

func NewCTRMode(initialCounter []byte) *CTRMode {
	return &CTRMode{counter: initialCounter}
}

func (c *CTRMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	return c.process(blocks, algorithm)
}

func (c *CTRMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	return c.process(blocks, algorithm)
}

func (c *CTRMode) process(blocks [][]byte, algorithm SymmetricAlgorithm) [][]byte {
	result := make([][]byte, len(blocks))
	currentCounter := make([]byte, len(c.counter))
	copy(currentCounter, c.counter)

	for i, block := range blocks {
		encrypted := algorithm.Encrypt(currentCounter)
		result[i] = xorBytes(block, encrypted)
		c.incrementCounter(currentCounter)
	}
	return result
}

func (c *CTRMode) incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= 0; i-- {
		counter[i]++
		if counter[i] != 0 {
			break
		}
	}
}

func (c *CTRMode) RequiresIV() bool { return true }
func (c *CTRMode) GetName() string  { return "CTR" }

type PCBCMode struct{}

// type check
var _ Mode = (*PCBCMode)(nil)

func (p *PCBCMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for i, block := range blocks {
		xored := xorBytes(block, prev)
		encrypted := algorithm.Encrypt(xored)
		result[i] = encrypted
		prev = xorBytes(block, encrypted)
	}
	return result
}

func (p *PCBCMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	prev := make([]byte, len(iv))
	copy(prev, iv)

	for i, block := range blocks {
		decrypted := algorithm.Decrypt(block)
		result[i] = xorBytes(decrypted, prev)
		prev = xorBytes(block, result[i])
	}
	return result
}

func (p *PCBCMode) RequiresIV() bool { return true }
func (p *PCBCMode) GetName() string  { return "PCBC" }

type RandomDeltaMode struct{}

// type check
var _ Mode = (*RandomDeltaMode)(nil)

func (r *RandomDeltaMode) Encrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))

	for i, block := range blocks {
		delta := make([]byte, len(block))
		_, err := rand.Read(delta)
		if err != nil {
			panic(err)
		}

		modified := xorBytes(block, delta)
		encrypted := algorithm.Encrypt(modified)

		encryptedDelta := algorithm.Encrypt(delta)
		result[i] = append(encrypted, encryptedDelta...)
	}
	return result
}

func (r *RandomDeltaMode) Decrypt(blocks [][]byte, algorithm SymmetricAlgorithm, iv []byte) [][]byte {
	result := make([][]byte, len(blocks))
	halfSize := len(blocks[0]) / 2

	for i, block := range blocks {
		dataPart := block[:halfSize]
		deltaPart := block[halfSize:]

		delta := algorithm.Decrypt(deltaPart)

		decrypted := algorithm.Decrypt(dataPart)

		result[i] = xorBytes(decrypted, delta)
	}
	return result
}

func (r *RandomDeltaMode) RequiresIV() bool { return false }
func (r *RandomDeltaMode) GetName() string  { return "RandomDelta" }

func xorBytes(a, b []byte) []byte {
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}
