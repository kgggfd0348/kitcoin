package ktcoin

import (
	"net"
	"os"
	"fmt"
	"net/rpc"
	"crypto/rsa"
	"crypto"
	"crypto/rand"
)

type BlockChainServer struct {
	blockchain *BlockChain
}

func (s *BlockChainServer) Transact(tx Transaction, accepted *bool) error {
	// make a genesis tx
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	genesisTx, err := NewTransaction(make([]Transaction, 0), key, tx.Sender, 25)
	if err != nil {
		return err
	}
	err = s.blockchain.addNextBlock([]Transaction{*genesisTx, tx})
	return err
}

func (s *BlockChainServer) GetOpenInputs(key rsa.PublicKey, openInputs *map[SHA]int) error {
	*openInputs = s.blockchain.GetOpenInputs(key)
	return nil
}

func RunNode() {
	bc := NewBlockChain()
	server := BlockChainServer { &bc }

	// Build a seed transaction to serve as input
	key, err := LoadKey("id_rsa")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	seedOutputs := make(map[string]int)
	// Give sender 2 coins to send
	seedOutputs[publicKeyString(key.PublicKey)] = 25
	bytes, _ := bytesToSign(key.PublicKey, []SHA{})
	seedSignature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, bytes[:])
	seedTransaction := Transaction{[]SHA{}, key.PublicKey, key.PublicKey, seedOutputs, seedSignature}
	err = server.blockchain.addNextBlock([]Transaction{seedTransaction})
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(server.blockchain)

	rpc.Register(&server)
	ln, err := net.Listen("tcp", ":8000")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	rpc.Accept(ln) 
}
