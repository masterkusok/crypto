package cipher

// Mode defines the cipher mode of operation.
type Mode int

const (
	// ECB is Electronic Codebook mode.
	ECB Mode = iota
	// CBC is Cipher Block Chaining mode.
	CBC
	// PCBC is Propagating Cipher Block Chaining mode.
	PCBC
	// CFB is Cipher Feedback mode.
	CFB
	// OFB is Output Feedback mode.
	OFB
	// CTR is Counter mode.
	CTR
	// RandomDelta is a custom mode with random delta values.
	RandomDelta
)
