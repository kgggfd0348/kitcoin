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
	sender    *rsa.PublicKey
	recipient *rsa.PublicKey
	outputs   map[*rsa.PublicKey]int
	signature []byte
}

func (t Transaction) String() string {
	return fmt.Sprintf("<Transaction %x>", t.signature)
}

// Computes the hash of a transaction by concatenating the hashes of
// the transaction's inputs with the key of the transaction's
// recipient.
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

func bytesToSign(recipient *rsa.PublicKey, inputHashes []SHA) (SHA, error) {
	bytesToHash, err := x509.MarshalPKIXPublicKey(recipient)
	if err != nil {
		var empty SHA
		return empty, err
	}
	for _, inputHash := range inputHashes {
		bytesToHash = append(bytesToHash, inputHash[:]...)
	}
	return sha256.Sum256(bytesToHash), nil
}

// Creates a new transaction struct, verifying that the input
// transactions have enough funds and sending any remaining funds from
// the input transactions back to the sender.
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

	inputHashes := make([]SHA, 0)
	for _, input := range inputs {
		hash, err := input.Hash()
		inputHashes = append(inputHashes, hash)
		if err != nil {
			return nil, err
		}
	}

	hashed, err := bytesToSign(recipient, inputHashes)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}

	senderPubKey := &sender.PublicKey

	return &Transaction{
		inputHashes,
		senderPubKey,
		recipient,
		outputs,
		signature,
	}, nil
}
