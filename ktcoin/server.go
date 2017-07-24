package ktcoin

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
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

type GetBlockRequest struct {
	sha             SHA
	callbackChannel chan Block
}

type NewBlockNotice struct {
	block Block
}

type RPCHandler interface {
	rpcHandle(server *BlockChainServer)
}

func (req TransactionRequest) rpcHandle(server *BlockChainServer) {
	err := server.blockchain.Verify(&req.tx)
	if err == nil {
		server.openTransactions = append(server.openTransactions, req.tx)
	}
	req.callbackChannel <- err
}

func (req OpenInputRequest) rpcHandle(server *BlockChainServer) {
	req.callbackChannel <- server.blockchain.GetOpenInputs(req.key)
}

func (req GetBlockRequest) rpcHandle(server *BlockChainServer) {
	req.callbackChannel <- server.blockchain.blocks[req.sha]
}

func (notice NewBlockNotice) rpcHandle(server *BlockChainServer) {
	// Validate the block.  1. Transactions must be valid.  2. Block
	// must hash to a difficult-enough SHA.  3. Block's previous hash
	// must equal s.blockchain.latestBlock, or link back to it
	// eventually.
	for i, t := range notice.block.Transactions {
		if i > 0 {
			err := server.blockchain.Verify(&t)
			if err != nil {
				fmt.Println(err)
				return
			}
		}
		// TODO: validate the first special tx
	}

	if !notice.block.isValid(NonceDifficulty) {
		fmt.Println("block hash does not satisfy proof of work")
		return
	}

	if notice.block.PrevHash != server.blockchain.latestBlock {
		fmt.Println("block is not next in the chain")
		return
	}

	fmt.Println("Accepting block.")
	blockSha := notice.block.Hash()
	server.blockchain.blocks[blockSha] = notice.block
	server.blockchain.latestBlock = blockSha
}

type BlockChainServer struct {
	requests         chan RPCHandler
	knownNodes       []string
	openTransactions []Transaction
	blockchain       *BlockChain
	currentNonce     int
}

//// Procedures for client-server communication

func (s *BlockChainServer) Transact(tx Transaction, accepted *bool) error {
	callbackChannel := make(chan error)
	txReq := TransactionRequest{tx, callbackChannel}
	s.requests <- txReq

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
	s.requests <- openInputRequest

	*openInputs = <-callbackChannel
	return nil
}

//// Procedures for server-to-server communication

func (s *BlockChainServer) GetBlock(sha SHA, block *Block) error {
	cb := make(chan Block)
	s.requests <- GetBlockRequest{sha, cb}
	*block = <-cb
	if block == nil {
		return errors.New("nonexistent block")
	}
	return nil
}

func (s *BlockChainServer) NewBlock(block Block, accepted *bool) error {
	s.requests <- NewBlockNotice{block}
	return nil
}

func (s *BlockChainServer) NewTransaction(transaction Transaction, accepted *bool) error {
	//TODO
	return nil
}

func runServer(server *BlockChainServer, key *rsa.PrivateKey) {
	fmt.Println("Running server...")
	for {
		select {
		case req := <-server.requests:
			req.rpcHandle(server)
		// Otherwise keep mining for blocks
		default:
			// Hack: in order to make each coin unique, the
			// transaction that initiates it has a fake input SHA,
			// which is the SHA of the previous block.

			outputs := make(map[string]int)
			outputs[publicKeyString(key.PublicKey)] = 25
			inputs := []SHA{server.blockchain.latestBlock}
			toSign, _ := bytesToSign(key.PublicKey, inputs)
			signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, toSign[:])
			genesisTx := Transaction{
				inputs,
				key.PublicKey,
				key.PublicKey,
				outputs,
				signature,
			}
			txs := append([]Transaction{genesisTx}, server.openTransactions...)

			err = server.blockchain.addNextBlock(NonceDifficulty, NonceAttempts, server.currentNonce, txs)
			if err != nil {
				server.currentNonce += NonceAttempts
				if err.Error() != "limit reached" {
					fmt.Println(err)
				}
			} else {
				server.openTransactions = make([]Transaction, 0)
				fmt.Println("New Block found")
				latestBlock := server.blockchain.blocks[server.blockchain.latestBlock]
				fmt.Println("Block: ", &latestBlock)
				for i, node := range server.knownNodes {
					fmt.Printf("Sending block to node %d (%s)\n", i, node)
					client, err := rpc.Dial("tcp", node+":8000")
					if err != nil {
						fmt.Println(err)
						break
					}

					var result bool // unused
					go func() {
						client.Call("BlockChainServer.NewBlock", latestBlock, &result)
						if err != nil {
							fmt.Println(err)
						}
					}()
				}
			}
		}
	}
}

func RunNode(knownNodes []string, key *rsa.PrivateKey) {
	bc := NewBlockChain()
	requests := make(chan RPCHandler)
	server := BlockChainServer{
		requests,
		knownNodes,
		[]Transaction{},
		&bc,
		0,
	}

	rpc.Register(&server)
	ln, err := net.Listen("tcp", ":8000")

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	go runServer(&server, key)
	rpc.Accept(ln)
}
