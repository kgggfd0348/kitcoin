package ktcoin

import (
	"crypto/rsa"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"sync"
)

type BlockChainServer struct {
	mu               *sync.Mutex
	knownNodes       []string
	openTransactions []Transaction
	blockchain       *BlockChain
	//  candidateChains	 ???
}

func (s *BlockChainServer) Transact(tx Transaction, accepted *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	err := s.blockchain.Verify(&tx)
	if err == nil {
		s.openTransactions = append(s.openTransactions, tx)
		*accepted = true
		return nil
	} else {
		return err
	}
}

func (s *BlockChainServer) GetOpenInputs(key rsa.PublicKey, openInputs *map[SHA]int) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	*openInputs = s.blockchain.GetOpenInputs(key)
	return nil
}

func mineBlocks(server *BlockChainServer, key *rsa.PrivateKey) {
	for {
		server.mu.Lock()

		genesisTx, err := NewTransaction(make([]Transaction, 0), key, key.PublicKey, 25)
		txs := append([]Transaction{*genesisTx}, server.openTransactions...)

		err = server.blockchain.addNextBlock(1, 100, txs)
		if err != nil {
			fmt.Println(err)
		} else {
			server.openTransactions = make([]Transaction, 0)
			// Broadcast the new block!
		}

		server.mu.Unlock()
	}
}

func RunNode(knownNodes []string, key *rsa.PrivateKey) {
	bc := NewBlockChain()
	mutex := sync.Mutex{}
	server := BlockChainServer{ &mutex, knownNodes, []Transaction{}, &bc}

	rpc.Register(&server)
	ln, err := net.Listen("tcp", ":8000")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	go mineBlocks(&server, key)
	rpc.Accept(ln)
}
