package ktcoin

import (
	"crypto/rsa"
	"fmt"
	"net"
	"net/rpc"
	"os"
)

const NonceAttempts = 10000

const NonceDifficulty = 2

type TransactionRequest struct {
	tx              Transaction
	callbackChannel chan error
}

type OpenInputRequest struct {
	key             rsa.PublicKey
	callbackChannel chan map[SHA]int
}

type BlockChainServer struct {
	incomingTransactions chan TransactionRequest
	openInputRequests    chan OpenInputRequest
	knownNodes           []string
	openTransactions     []Transaction
	blockchain           *BlockChain
	currentNonce         int
	//  candidateChains	 ???
}

func (s *BlockChainServer) Transact(tx Transaction, accepted *bool) error {
	callbackChannel := make(chan error)
	txReq := TransactionRequest{tx, callbackChannel}
	s.incomingTransactions <- txReq

	err := <-callbackChannel
	if err == nil {
		*accepted = true
		return nil
	} else {
		return err
	}
}

func (s *BlockChainServer) GetOpenInputs(key rsa.PublicKey, openInputs *map[SHA]int) error {
	callbackChannel := make(chan map[SHA]int)
	openInputRequest := OpenInputRequest{key, callbackChannel}
	s.openInputRequests <- openInputRequest

	*openInputs = <-callbackChannel
	return nil
}

func runServer(server *BlockChainServer, key *rsa.PrivateKey) {
	for {
		select {
		// If there's a new transaction, handle it
		case txReq := <-server.incomingTransactions:
			err := server.blockchain.Verify(&txReq.tx)
			if err == nil {
				server.openTransactions = append(server.openTransactions, txReq.tx)
			}
			txReq.callbackChannel <- err
		// If there's a request for open inputs, handle it
		case openInputReq := <-server.openInputRequests:
			openInputReq.callbackChannel <- server.blockchain.GetOpenInputs(openInputReq.key)
		// Otherwise keep mining for blocks
		default:
			genesisTx, err := NewTransaction(make([]Transaction, 0), key, key.PublicKey, 25)
			txs := append([]Transaction{*genesisTx}, server.openTransactions...)

			err = server.blockchain.addNextBlock(NonceDifficulty, NonceAttempts, server.currentNonce, txs)
			if err != nil {
				server.currentNonce += NonceAttempts
				if err.Error() != "limit reached" {
					fmt.Println(err)
				}
			} else {
				server.openTransactions = make([]Transaction, 0)
				fmt.Println("New Block found")
				// Broadcast the new block!
			}
		}
	}
}

func RunNode(knownNodes []string, key *rsa.PrivateKey) {
	bc := NewBlockChain()
	txRequestChan := make(chan TransactionRequest)
	openInputRequestChan := make(chan OpenInputRequest)
	server := BlockChainServer{txRequestChan, openInputRequestChan, knownNodes, []Transaction{}, &bc, 0}

	rpc.Register(&server)
	ln, err := net.Listen("tcp", ":8000")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	go runServer(&server, key)
	rpc.Accept(ln)
}
