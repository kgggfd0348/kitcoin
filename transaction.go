package ktcoin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
)

// A transaction consists of inputs (the previous transactions where
//  the current owner received coins) and outputs (a map of public
//  keys to how much they are allocated of the pooled input
//  transaction coins).  To be valid, a transaction must obey several
//  properties:
//
//  1. None of the input transactions have been used as an input
//  already.

//  2. The total number of coins in the inputs equals the number of
//  coins in the output, except for one special transaction per block
//  which creates new coins.

//  3. The signature must match the owner of all the input
//     transactions (they all have to be owned by the same key)
type Transaction struct {
	inputs    []SHA
	outputs   map[*rsa.PublicKey]int
	signature []byte
}

func (t Transaction) String() string {
	return fmt.Sprintf("<Transaction %x>", t.signature)
}

func (t *Transaction) Hash() (SHA, error) {
	toHash := make([]byte, 0)
	for _, input := range t.inputs {
		toHash = append(toHash, input[:]...)
	}

	for key, _ := range t.outputs {
		keyBytes, err := x509.MarshalPKIXPublicKey(key)
		if err != nil {
			var empty SHA
			return empty, err
		}
		toHash = append(toHash, keyBytes...)
	}

	toHash = append(toHash, t.signature...)

	hash := sha256.Sum256(toHash)
	return hash, nil
}

func NewTransaction(inputs []Transaction, sender *rsa.PrivateKey, recipient *rsa.PublicKey, amount int) (*Transaction, error) {
	inputTotal := 0
	for _, inputTx := range inputs {
		inputTotal += inputTx.outputs[&sender.PublicKey]
	}

	if amount > inputTotal {
		return nil, errors.New("insufficient amount in input transactions")
	}

	change := inputTotal - amount

	outputs := make(map[*rsa.PublicKey]int)
	outputs[recipient] = amount

	if change > 0 {
		outputs[&sender.PublicKey] = change
	}

	bytesToHash, err := x509.MarshalPKIXPublicKey(recipient)
	if err != nil {
		return nil, err
	}

	inputHashes := make([]SHA, 0)
	for _, input := range inputs {
		hash, err := input.Hash()
		inputHashes = append(inputHashes, hash)
		if err != nil {
			return nil, err
		}
		bytesToHash = append(bytesToHash, hash[:]...)
	}

	hashed := sha256.Sum256(bytesToHash)
	signature, err := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, hashed[:])

	if err != nil {
		return nil, err
	}

	return &Transaction{
		inputHashes,
		outputs,
		signature,
	}, nil
}
