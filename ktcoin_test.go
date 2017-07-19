package main

import (
	"testing"
	"crypto/rsa"
	"crypto/rand"
	"fmt"
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
	
}
