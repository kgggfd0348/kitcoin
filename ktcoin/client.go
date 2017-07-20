package ktcoin

import (
	"crypto/rsa"
	"net/rpc"
	"fmt"
	"crypto/rand"
	"crypto"
)

func SendTransaction(sender *rsa.PrivateKey, recipient *rsa.PublicKey, amount int) error {
	// get valid input shas
	// pick enough of them for amount or exit with error
	// send tx
	// communicate result
	client, err := rpc.Dial("tcp", "localhost:8000")
	if err != nil {
		return err
	}

	reply := make(map[SHA]int)
	err = client.Call("BlockChainServer.GetOpenInputs", &sender.PublicKey, &reply)
	if err != nil {
		return err
	}

	shas := make([]SHA, 0)
	inputTotal := 0
	for sha, inputAmount := range reply {
		shas = append(shas, sha)
		inputAmount += inputTotal
	}

	var success bool
	hashed, _ := bytesToSign(*recipient, shas)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, hashed[:])
	outputs := make(map[string]int) 
	outputs[publicKeyString(sender.PublicKey)] = inputTotal - amount
	outputs[publicKeyString(*recipient)] = amount

	tx := Transaction{shas, sender.PublicKey, *recipient, outputs, signature}

	fmt.Println("running the new code")
	err = client.Call("BlockChainServer.Transact", tx, &success)
	if err != nil {
		return err
	}

	fmt.Println(reply)
	return nil
}
