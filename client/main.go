package main

import (
	"github.com/loganmhb/ktcoin/ktcoin"
	"flag"
	"fmt"
)

func main() {
	senderKeyFile := flag.String("key", "id_rsa", "File of the sender's private key")
	recipientKeyFile := flag.String("to", "", "File of the recipient's public key")
	generateKey := flag.Bool("generate", false, "Generate a new private key")
	amount := flag.Int("amount", 0, "Amount to send")
	flag.Parse()

	if *generateKey {
		ktcoin.GenerateKey(*senderKeyFile)
	}
	senderKey, err := ktcoin.LoadKey(*senderKeyFile)
	if err != nil {
		fmt.Println(err)
	}
	recipientKey, err := ktcoin.LoadPublicKey(*recipientKeyFile)
	if err != nil {
		fmt.Println(err)
	}
	err = ktcoin.SendTransaction(senderKey, recipientKey, *amount)
	if err != nil {
		fmt.Println(err)
	}
}
