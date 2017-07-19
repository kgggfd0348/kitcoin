package ktcoin

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
)

func TestTransfer(t *testing.T) {
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)
	sender, _ := rsa.GenerateKey(rand.Reader, 2048)

	coin := make(Coin, 0)

	// Make money out of thin air.
	err := coin.transfer(sender, &sender.PublicKey)
	if err != nil {
		t.Error(err)
	}

	// Transfer the coin.
	err = coin.transfer(sender, &recipient.PublicKey)
	if err != nil {
		t.Error(err)
	}

	if len(coin) != 2 {
		t.Error("something went wrong")
		fmt.Println(coin)
	}
}

func TestVerify(t *testing.T) {
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)
	sender, _ := rsa.GenerateKey(rand.Reader, 2048)

	coin := make(Coin, 0)

	// Make money out of thin air.
	err := coin.transfer(sender, &sender.PublicKey)
	if err != nil {
		t.Error(err)
	}

	// Transfer the coin.
	err = coin.transfer(sender, &recipient.PublicKey)
	if err != nil {
		t.Error(err)
	}

	err = coin.Verify()
	if err != nil {
		t.Error(err)
	}

	err = coin.transfer(sender, &recipient.PublicKey)
	if err != nil {
		t.Error(err)
	}

	err = coin.Verify()
	if err == nil {
		t.Error(err)
	}
}

func TestAddBlock(t *testing.T) {
	bc := NewBlockChain()
	transactions := make([]Transaction, 0)
	transactionBytes := make([]byte, 0)
	transactionBytes = append(transactionBytes, []byte("test")...)
	recipient, _ := rsa.GenerateKey(rand.Reader, 2048)
	signature := make([]byte, 0)
	transactions = append(transactions, Transaction{transactionBytes, &recipient.PublicKey, signature})
	bc.addNextBlock(transactions)
	if len(bc.blocks) != 2 {
		t.Fail()
	}
}
