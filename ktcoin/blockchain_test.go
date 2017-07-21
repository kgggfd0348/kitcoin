package ktcoin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestVerifyTransaction(t *testing.T) {
	bc := NewBlockChain()
	sender, _ := rsa.GenerateKey(rand.Reader, 2048)
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Build a dummy transaction to serve as input
	dummyOutputs := make(map[string]int)
	// Give sender 2 coins to send
	dummyOutputs[publicKeyString(sender.PublicKey)] = 25
	bytes, _ := bytesToSign(sender.PublicKey, []SHA{})
	dummySignature, _ := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, bytes[:])
	inputTransaction := Transaction{[]SHA{}, sender.PublicKey, sender.PublicKey, dummyOutputs, dummySignature}

	inputs := []Transaction{
		inputTransaction,
	}

	tx, err := NewTransaction(inputs, sender, recipient.PublicKey, 1)
	if err != nil {
		t.Error(err)
	}

	verifyErr := bc.Verify(tx)

	// Will fail because input transactions are not in blockchain
	if verifyErr == nil {
		t.Fail()
	}

	err = bc.addNextBlock(1, 10000, inputs)
	if err != nil {
		t.Error(err)
	}

	verifyErr = bc.Verify(tx)
	// Will succeed because input transactions are now in blockchain
	if verifyErr != nil {
		t.Error(err)
	}
}

func TestAddBlock(t *testing.T) {
	bc := NewBlockChain()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	transactions := make([]Transaction, 0)

	recipient := key.PublicKey
	inputs := make([]SHA, 0)

	toSign, _ := bytesToSign(recipient, inputs)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, toSign[:])
	outputs := make(map[string]int, 0)
	outputs[publicKeyString(recipient)] = 25
	tx := Transaction{
		inputs,
		key.PublicKey,
		recipient,
		outputs,
		signature,
	}
	transactions = append(transactions, tx)
	err := bc.addNextBlock(1, 10000, transactions)
	if err != nil {
		t.Error(err)
	}
	if len(bc.blocks) != 2 {
		t.Fail()
	}
}
