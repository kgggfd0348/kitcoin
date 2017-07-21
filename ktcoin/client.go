package ktcoin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/rpc"
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
	fmt.Printf("Open Inputs: %v", reply)
	if err != nil {
		return err
	}

	shas := make([]SHA, 0)
	inputTotal := 0
	for sha, inputAmount := range reply {
		shas = append(shas, sha)
		inputTotal += inputAmount
	}

	var success bool
	hashed, _ := bytesToSign(*recipient, shas)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, sender, crypto.SHA256, hashed[:])
	outputs := make(map[string]int)
	change := inputTotal - amount
	if change > 0 {
		outputs[publicKeyString(sender.PublicKey)] = change
	}
	outputs[publicKeyString(*recipient)] = amount

	tx := Transaction{shas, sender.PublicKey, *recipient, outputs, signature}
	fmt.Print(outputs)

	fmt.Println("running the new code")
	err = client.Call("BlockChainServer.Transact", tx, &success)
	if err != nil {
		return err
	}

	fmt.Printf("Success? %v", success)
	return nil
}
