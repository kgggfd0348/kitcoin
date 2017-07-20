package ktcoin

import (
	"crypto/rsa"
	"net/rpc"
	"fmt"
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

	fmt.Println(reply)
	return nil
}
