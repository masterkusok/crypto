// Package main demonstrates DES and DEAL encryption with various modes.
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/masterkusok/crypto/cipher"
	"github.com/masterkusok/crypto/cipher/deal"
	"github.com/masterkusok/crypto/cipher/des"
	"github.com/masterkusok/crypto/cipher/rc6"
	"github.com/masterkusok/crypto/cipher/rsa"
	"github.com/masterkusok/crypto/cipher/tripledes"
)

func main() {
	ctx := context.Background()

	// Generate random key and IV
	desKey := make([]byte, 8)
	dealKey := make([]byte, 24)
	iv := make([]byte, 8)
	rand.Read(desKey)
	rand.Read(dealKey)
	rand.Read(iv)

	// Test data
	plaintext := []byte("Hello, this is a test message for cryptography lab!")

	fmt.Println("=== DES Encryption Demo ===")
	testDES(ctx, desKey, iv, plaintext)

	fmt.Println("\n=== DEAL Encryption Demo ===")
	testDEAL(ctx, dealKey, plaintext)

	fmt.Println("\n=== TripleDES Encryption Demo ===")
	testTripleDES(ctx, plaintext)

	fmt.Println("\n=== RC6 Encryption Demo ===")
	testRC6(ctx, plaintext)

	fmt.Println("\n=== File Encryption Demo ===")
	testFileEncryption(ctx, desKey, iv)

	fmt.Println("\n=== RSA Demo ===")
	testRSA(ctx)
}

func testDES(ctx context.Context, key, iv, plaintext []byte) {
	modes := []cipher.Mode{cipher.ECB, cipher.CBC, cipher.CFB, cipher.OFB, cipher.CTR}
	modeNames := []string{"ECB", "CBC", "CFB", "OFB", "CTR"}

	for i, mode := range modes {
		fmt.Printf("\nMode: %s\n", modeNames[i])

		cipherCtx, err := cipher.NewCipherContext(
			des.NewDES(),
			key,
			mode,
			cipher.PKCS7,
			iv,
		)
		if err != nil {
			log.Printf("Failed to create cipher context: %v", err)
			continue
		}

		encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
		if err != nil {
			log.Printf("Encryption failed: %v", err)
			continue
		}

		decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
		if err != nil {
			log.Printf("Decryption failed: %v", err)
			continue
		}

		fmt.Printf("Original:  %s\n", plaintext)
		fmt.Printf("Encrypted: %x\n", encrypted[:min(32, len(encrypted))])
		fmt.Printf("Decrypted: %s\n", decrypted)
		fmt.Printf("Match: %v\n", string(plaintext) == string(decrypted))
	}
}

func testDEAL(ctx context.Context, key, plaintext []byte) {
	iv := make([]byte, 16)
	rand.Read(iv)

	cipherCtx, err := cipher.NewCipherContext(
		deal.NewDEAL(),
		key,
		cipher.CBC,
		cipher.PKCS7,
		iv,
	)
	if err != nil {
		log.Fatalf("Failed to create DEAL context: %v", err)
	}

	encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Fatalf("DEAL encryption failed: %v", err)
	}

	decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Fatalf("DEAL decryption failed: %v", err)
	}

	fmt.Printf("Original:  %s\n", plaintext)
	fmt.Printf("Encrypted: %x\n", encrypted[:min(32, len(encrypted))])
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(plaintext) == string(decrypted))
}

func testTripleDES(ctx context.Context, plaintext []byte) {
	key := make([]byte, 24)
	rand.Read(key)
	iv := make([]byte, 8)
	rand.Read(iv)

	cipherCtx, err := cipher.NewCipherContext(
		tripledes.NewTripleDES(),
		key,
		cipher.CBC,
		cipher.PKCS7,
		iv,
	)
	if err != nil {
		log.Fatalf("Failed to create TripleDES context: %v", err)
	}

	encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Fatalf("TripleDES encryption failed: %v", err)
	}

	decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Fatalf("TripleDES decryption failed: %v", err)
	}

	fmt.Printf("Original:  %s\n", plaintext)
	fmt.Printf("Encrypted: %x\n", encrypted[:min(32, len(encrypted))])
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(plaintext) == string(decrypted))
}

func testFileEncryption(ctx context.Context, key, iv []byte) {
	testData := "🫩"

	inputFile := "test_input.txt"
	encryptedFile := "test_encrypted.bin"
	decryptedFile := "test_decrypted.txt"

	if err := os.WriteFile(inputFile, []byte(testData), 0o644); err != nil {
		log.Printf("Failed to create test file: %v", err)
		return
	}
	defer os.Remove(inputFile)
	defer os.Remove(encryptedFile)
	defer os.Remove(decryptedFile)

	cipherCtx, err := cipher.NewCipherContext(
		des.NewDES(),
		key,
		cipher.CBC,
		cipher.PKCS7,
		iv,
	)
	if err != nil {
		log.Printf("Failed to create cipher context: %v", err)
		return
	}

	fmt.Printf("Original file content: %#x (1 null byte)\n", testData)

	if err = cipherCtx.EncryptFile(ctx, inputFile, encryptedFile); err != nil {
		log.Printf("File encryption failed: %v", err)
		return
	}

	encryptedData, _ := os.ReadFile(encryptedFile)
	fmt.Printf("Encrypted file: %x\n", encryptedData)

	if err = cipherCtx.DecryptFile(ctx, encryptedFile, decryptedFile); err != nil {
		log.Printf("File decryption failed: %v", err)
		return
	}

	decrypted, err := os.ReadFile(decryptedFile)
	if err != nil {
		log.Printf("Failed to read decrypted file: %v", err)
		return
	}

	fmt.Printf("Decrypted file content: %#x\n", decrypted)

	match := len(testData) == len(decrypted)
	if match {
		for i := range testData {
			if testData[i] != decrypted[i] {
				match = false
				break
			}
		}
	}
	fmt.Printf("Match: %v\n", match)
}

func testRSA(ctx context.Context) {
	rsaCipher, err := rsa.NewRSA(1024)
	if err != nil {
		log.Fatalf("Failed to create RSA: %v", err)
	}

	plaintext := []byte("RSA encryption test!")
	encrypted, err := rsaCipher.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Fatalf("RSA encryption failed: %v", err)
	}

	decrypted, err := rsaCipher.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Fatalf("RSA decryption failed: %v", err)
	}

	fmt.Printf("Original:  %s\n", plaintext)
	fmt.Printf("Encrypted: %x... (%d bytes)\n", encrypted[:min(32, len(encrypted))], len(encrypted))
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(plaintext) == string(decrypted))

	// Test Wiener attack protection
	vulnerable := rsa.IsVulnerableToWiener(rsaCipher.PublicKey())
	fmt.Printf("Vulnerable to Wiener attack: %v\n", vulnerable)
}

func testRC6(ctx context.Context, plaintext []byte) {
	key := make([]byte, 16)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)

	cipherCtx, err := cipher.NewCipherContext(
		rc6.NewRC6(),
		key,
		cipher.CBC,
		cipher.PKCS7,
		iv,
	)
	if err != nil {
		log.Fatalf("Failed to create RC6 context: %v", err)
	}

	encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Fatalf("RC6 encryption failed: %v", err)
	}

	decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Fatalf("RC6 decryption failed: %v", err)
	}

	fmt.Printf("Original:  %s\n", plaintext)
	fmt.Printf("Encrypted: %x\n", encrypted[:min(32, len(encrypted))])
	fmt.Printf("Decrypted: %s\n", decrypted)
	fmt.Printf("Match: %v\n", string(plaintext) == string(decrypted))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
