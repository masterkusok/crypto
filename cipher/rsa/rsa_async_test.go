package rsa

import (
	"bytes"
	"context"
	"testing"
	"time"

	cryptoMath "github.com/masterkusok/crypto/math"
)

func TestEncryptDecryptAsync(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	if err := rsa.GenerateKeyPair(); err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	message := []byte("test message")
	ctx := context.Background()

	resultChan, errChan := rsa.EncryptAsync(ctx, message)
	var encrypted []byte
	select {
	case encrypted = <-resultChan:
	case err := <-errChan:
		t.Fatalf("encryption failed: %v", err)
	}

	resultChan, errChan = rsa.DecryptAsync(ctx, encrypted)
	var decrypted []byte
	select {
	case decrypted = <-resultChan:
	case err := <-errChan:
		t.Fatalf("decryption failed: %v", err)
	}

	if !bytes.Equal(message, decrypted) {
		t.Errorf("expected %v, got %v", message, decrypted)
	}
}

func TestAsyncWithCancelledContext(t *testing.T) {
	rsa := NewRSA(cryptoMath.NewMillerRabinTest(), 0.99, 512)
	if err := rsa.GenerateKeyPair(); err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, errChan := rsa.EncryptAsync(ctx, []byte("test"))
	select {
	case err := <-errChan:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for error")
	}
}
