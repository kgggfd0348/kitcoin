package ktcoin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestNewTransaction(t *testing.T) {
	sender, _ := rsa.GenerateKey(rand.Reader, 2048)
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Build a dummy transaction to serve as input
	dummyOutputs := make(map[string]int)
	// Give sender 2 coins to send
	dummyOutputs[publicKeyString(sender.PublicKey)] = 25
	bytesToSign := sha256.Sum256([]byte("dummy data"))
	dummySignature, _ := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, bytesToSign[:])
	dummyTransaction := Transaction{[]SHA{}, sender.PublicKey, recipient.PublicKey, dummyOutputs, dummySignature}

	inputs := []Transaction{
		dummyTransaction,
	}

	tx, err := NewTransaction(inputs, sender, recipient.PublicKey, 1)

	if err != nil {
		t.Error(err)
	}

	dummyTxHash := dummyTransaction.Hash()

	if len(tx.Inputs) != 1 || tx.Inputs[0] != dummyTxHash {
		t.Fail()
	}

	// Check for change.
	if tx.Outputs[publicKeyString(sender.PublicKey)] != 24 || tx.Outputs[publicKeyString(recipient.PublicKey)] != 1 {
		t.Fail()
	}

	// Try sending too much.
	_, err = NewTransaction(inputs, sender, recipient.PublicKey, 30)

	if err == nil {
		t.Fail()
	}
}
