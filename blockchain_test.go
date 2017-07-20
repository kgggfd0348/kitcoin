package ktcoin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func TestVerifyTransaction(t *testing.T) {
	bc := NewBlockChain()
	sender, _ := rsa.GenerateKey(rand.Reader, 2048)
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Build a dummy transaction to serve as input
	dummyOutputs := make(map[*rsa.PublicKey]int)
	// Give sender 2 coins to send
	dummyOutputs[&sender.PublicKey] = 2
	bytesToSign := sha256.Sum256([]byte("dummy data"))
	dummySignature, _ := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, bytesToSign[:])
	dummyTransaction := Transaction{[]SHA{}, &sender.PublicKey, &recipient.PublicKey, dummyOutputs, dummySignature}

	inputs := []Transaction{
		dummyTransaction,
	}

	tx, err := NewTransaction(inputs, sender, &recipient.PublicKey, 1)
	if err != nil {
		t.Error(err)
	}
	verifyErr := bc.Verify(tx)
	// Will fail because dummyTransaction is not in blockchain
	if verifyErr == nil {
		t.Fail()
	}
}
