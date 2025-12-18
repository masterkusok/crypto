package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/masterkusok/crypto/cipher/rsa"
)

func main() {
	ctx := context.Background()

	fmt.Println("=== RSA Key Generation ===")
	testKeyGeneration()

	fmt.Println("\n=== RSA Encryption/Decryption ===")
	testRSAEncryption(ctx)

	fmt.Println("\n=== RSA File Encryption ===")
	testRSAFileEncryption(ctx)

	fmt.Println("\n=== Wiener Attack Demo ===")
	testWienerAttack()
}

func testKeyGeneration() {
	start := time.Now()
	rsaCipher, err := rsa.NewRSA(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA keys: %v", err)
	}
	elapsed := time.Since(start)

	fmt.Printf("Generated 2048-bit RSA key pair in %v\n", elapsed)
	fmt.Printf("Public key (N): %d bits\n", rsaCipher.PublicKey().N.BitLen())
	fmt.Printf("Public exponent (E): %s\n", rsaCipher.PublicKey().E.String())
	fmt.Printf("Private exponent (D): %d bits\n", rsaCipher.PrivateKey().D.BitLen())

	// Check Wiener attack protection
	nSqrt := rsaCipher.PrivateKey().N
	nSqrt.Sqrt(nSqrt)
	nFourthRoot := nSqrt
	nFourthRoot.Sqrt(nFourthRoot)

	fmt.Printf("Protected against Wiener attack: %v\n", rsaCipher.PrivateKey().D.Cmp(nFourthRoot) > 0)
}

func testRSAEncryption(ctx context.Context) {
	rsaCipher, err := rsa.NewRSA(1024)
	if err != nil {
		log.Fatalf("Failed to create RSA: %v", err)
	}

	plaintext := []byte("Hello, RSA! This is a test message for encryption.")

	start := time.Now()
	encrypted, err := rsaCipher.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}
	encTime := time.Since(start)

	start = time.Now()
	decrypted, err := rsaCipher.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	decTime := time.Since(start)

	fmt.Printf("Original:  %s\n", plaintext)
	fmt.Printf("Encrypted: %x... (%d bytes)\n", encrypted[:32], len(encrypted))
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(plaintext) == string(decrypted))
	fmt.Printf("Encryption time: %v\n", encTime)
	fmt.Printf("Decryption time: %v\n", decTime)
}

func testRSAFileEncryption(ctx context.Context) {
	rsaCipher, err := rsa.NewRSA(2048)
	if err != nil {
		log.Fatalf("Failed to create RSA: %v", err)
	}

	// Create test file
	testData := []byte("This is a test file for RSA encryption.\nIt contains multiple lines.\nAnd some data: 0123456789\n")
	inputFile := "test_rsa_input.txt"
	encryptedFile := "test_rsa_encrypted.bin"
	decryptedFile := "test_rsa_decrypted.txt"

	if err := os.WriteFile(inputFile, testData, 0644); err != nil {
		log.Fatalf("Failed to create test file: %v", err)
	}
	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	fmt.Printf("Original file size: %d bytes\n", len(testData))

	start := time.Now()
	if err := rsaCipher.EncryptFile(ctx, inputFile, encryptedFile); err != nil {
		log.Fatalf("File encryption failed: %v", err)
	}
	encTime := time.Since(start)

	encData, _ := os.ReadFile(encryptedFile)
	fmt.Printf("Encrypted file size: %d bytes\n", len(encData))
	fmt.Printf("Encryption time: %v\n", encTime)

	start = time.Now()
	if err := rsaCipher.DecryptFile(ctx, encryptedFile, decryptedFile); err != nil {
		log.Fatalf("File decryption failed: %v", err)
	}
	decTime := time.Since(start)

	decrypted, _ := os.ReadFile(decryptedFile)
	fmt.Printf("Decrypted file size: %d bytes\n", len(decrypted))
	fmt.Printf("Decryption time: %v\n", decTime)

	match := string(testData) == string(decrypted)
	fmt.Printf("Match: %v\n", match)
}

func testWienerAttack() {
	// Generate a normal (protected) key
	rsaCipher, err := rsa.NewRSA(1024)
	if err != nil {
		log.Fatalf("Failed to create RSA: %v", err)
	}

	fmt.Println("Testing Wiener attack on protected key...")
	start := time.Now()
	recoveredD := rsa.WienerAttack(rsaCipher.PublicKey())
	elapsed := time.Since(start)

	if recoveredD == nil {
		fmt.Printf("✓ Wiener attack failed (key is protected) - took %v\n", elapsed)
	} else {
		fmt.Printf("✗ WARNING: Wiener attack succeeded! Key is vulnerable!\n")
		fmt.Printf("  Recovered D: %s\n", recoveredD.String())
	}

	// Check vulnerability
	vulnerable := rsa.IsVulnerableToWiener(rsaCipher.PublicKey())
	fmt.Printf("Key vulnerable to Wiener attack: %v\n", vulnerable)
}
