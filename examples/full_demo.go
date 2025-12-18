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

	fmt.Println("=== Cryptography Library Demo ===\n")

	fmt.Println("1. DES Encryption")
	testSymmetric(ctx, des.NewDES(), 8, "DES")

	fmt.Println("\n2. TripleDES Encryption")
	testSymmetric(ctx, tripledes.NewTripleDES(), 24, "3DES")

	fmt.Println("\n3. DEAL Encryption")
	testSymmetric(ctx, deal.NewDEAL(), 24, "DEAL")

	fmt.Println("\n4. RC6 Encryption")
	testSymmetric(ctx, rc6.NewRC6(), 16, "RC6")

	fmt.Println("\n5. RSA Encryption")
	testRSAFull(ctx)

	fmt.Println("\n6. File Encryption Test")
	testFileEncryption(ctx)
}

func testSymmetric(ctx context.Context, bc cipher.BlockCipher, keySize int, name string) {
	key := make([]byte, keySize)
	rand.Read(key)

	ivSize := bc.BlockSize()
	iv := make([]byte, ivSize)
	rand.Read(iv)

	cipherCtx, err := cipher.NewCipherContext(bc, key, cipher.CBC, cipher.PKCS7, iv)
	if err != nil {
		log.Printf("%s context creation failed: %v", name, err)
		return
	}

	plaintext := []byte("Test message for " + name)
	encrypted, err := cipherCtx.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Printf("%s encryption failed: %v", name, err)
		return
	}

	decrypted, err := cipherCtx.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Printf("%s decryption failed: %v", name, err)
		return
	}

	fmt.Printf("  Plaintext:  %s\n", plaintext)
	fmt.Printf("  Encrypted:  %x...\n", encrypted[:16])
	fmt.Printf("  Decrypted:  %s\n", decrypted)
	fmt.Printf("  Match: %v\n", string(plaintext) == string(decrypted))
}

func testRSAFull(ctx context.Context) {
	rsaCipher, err := rsa.NewRSA(2048)
	if err != nil {
		log.Fatalf("RSA creation failed: %v", err)
	}

	plaintext := []byte("Test message for RSA")
	encrypted, err := rsaCipher.EncryptBytes(ctx, plaintext)
	if err != nil {
		log.Fatalf("RSA encryption failed: %v", err)
	}

	decrypted, err := rsaCipher.DecryptBytes(ctx, encrypted)
	if err != nil {
		log.Fatalf("RSA decryption failed: %v", err)
	}

	fmt.Printf("  Plaintext:  %s\n", plaintext)
	fmt.Printf("  Encrypted:  %x... (%d bytes)\n", encrypted[:32], len(encrypted))
	fmt.Printf("  Decrypted:  %s\n", decrypted)
	fmt.Printf("  Match: %v\n", string(plaintext) == string(decrypted))
	fmt.Printf("  Wiener protected: %v\n", !rsa.IsVulnerableToWiener(rsaCipher.PublicKey()))
}

func testFileEncryption(ctx context.Context) {
	key := make([]byte, 8)
	rand.Read(key)
	iv := make([]byte, 8)
	rand.Read(iv)

	cipherCtx, _ := cipher.NewCipherContext(des.NewDES(), key, cipher.CBC, cipher.PKCS7, iv)

	testData := []byte("File encryption test data\n")
	os.WriteFile("test.txt", testData, 0644)
	defer os.Remove("test.txt")
	defer os.Remove("test.enc")
	defer os.Remove("test.dec")

	cipherCtx.EncryptFile(ctx, "test.txt", "test.enc")
	cipherCtx.DecryptFile(ctx, "test.enc", "test.dec")

	decrypted, _ := os.ReadFile("test.dec")
	fmt.Printf("  File encryption match: %v\n", string(testData) == string(decrypted))

	rsaCipher, _ := rsa.NewRSA(1024)
	os.WriteFile("test_rsa.txt", testData, 0644)
	defer os.Remove("test_rsa.txt")
	defer os.Remove("test_rsa.enc")
	defer os.Remove("test_rsa.dec")

	rsaCipher.EncryptFile(ctx, "test_rsa.txt", "test_rsa.enc")
	rsaCipher.DecryptFile(ctx, "test_rsa.enc", "test_rsa.dec")

	decryptedRSA, _ := os.ReadFile("test_rsa.dec")
	fmt.Printf("  RSA file encryption match: %v\n", string(testData) == string(decryptedRSA))
}
