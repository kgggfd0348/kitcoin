package ktcoin

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// A Block consists of the previous block's hash, the list of
// transactions it enacts, and a nonce.  For a block to be valid, the
// SHA256 hash must have sufficient leading zeroes to satisfy the
// proof of work property.
type Block struct {
	PrevHash     SHA
	Nonce        int
	Transactions []Transaction
}

func (block *Block) String() string {
	transactions := ""
	for _, t := range block.Transactions {
		transactions += t.String()
	}
	return fmt.Sprintf("{prevHash: %x,\n transactions: [%s]}", block.PrevHash, transactions)
}

type BlockChain struct {
	latestBlock      SHA
	blocks           map[SHA]Block
	openTransactions map[SHA]map[string]int
}

func (bc *BlockChain) String() string {
	blocks := ""
	for _, block := range bc.blocks {
		blocks += block.String()
	}
	return fmt.Sprintf("{blocks: [%s],\nopenTransactions: %d}", blocks, len(bc.openTransactions))
}

func NewBlockChain() BlockChain {
	genesisHash := sha256.Sum256([]byte("genesis"))
	blocks := make(map[SHA]Block)
	firstBlock := Block{genesisHash, 0, make([]Transaction, 0)}
	firstSha := firstBlock.Hash()
	blocks[firstSha] = firstBlock
	openTransactions := make(map[SHA]map[string]int)
	return BlockChain{
		firstSha,
		blocks,
		openTransactions,
	}
}

func (block *Block) Hash() SHA {
	contents := make([]byte, 0)
	contents = append(contents, block.PrevHash[:]...)
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, uint64(block.Nonce))
	contents = append(contents, nonceBytes...)

	for _, t := range block.Transactions {
		hashedTransaction := t.Hash()
		contents = append(contents, hashedTransaction[:]...)
	}

	hash := sha256.Sum256(contents)
	return hash
}

func (bc *BlockChain) GetOpenInputs(key rsa.PublicKey) map[SHA]int {
	openInputs := make(map[SHA]int)

	for sha, outputs := range bc.openTransactions {
		amount, isPresent := outputs[publicKeyString(key)]
		if isPresent {
			openInputs[sha] = amount
		}
	}

	return openInputs
}

func (block *Block) isValid(difficulty int) bool {
	hashedBlock := block.Hash()
	for i := 0; i < difficulty; i++ {
		if hashedBlock[i] != 0 {
			return false
		}
	}
	return true
}

func (bc *BlockChain) addNextBlock(difficulty int, limit int, nonce int, transactions []Transaction) error {
	// Verify transactions
	for i, t := range transactions {
		if i == 0 {
			// Special case: money from nothing
			outputTotal := 0
			for _, v := range t.Outputs {
				outputTotal += v
			}
			if outputTotal != 25 {
				return errors.New("Invalid genesis transaction: does not create 25 coins")
			}
		} else {
			err := bc.Verify(&t)
			if err != nil {
				fmt.Println("verification error")
				return err
			}
		}
	}

	// Look for the magic hash value
	prevHash := bc.latestBlock

	newBlock := Block{prevHash, nonce, transactions}

	for i := 0; !newBlock.isValid(difficulty); i++ {
		if i >= limit {
			return errors.New("limit reached")
		}
		newBlock.Nonce++
	}

	// Append the block to the chain
	newBlockSha := newBlock.Hash()
	bc.blocks[newBlockSha] = newBlock
	bc.latestBlock = newBlockSha

	for _, transaction := range transactions {
		for _, input := range transaction.Inputs {
			delete(bc.openTransactions[input], publicKeyString(transaction.Sender))
		}
		hashedTransaction := transaction.Hash()
		bc.openTransactions[hashedTransaction] = transaction.Outputs
	}
	return nil
}

// How to verify a transaction on the block chain:
// - Check that the
//   transaction is internally consistent (inputs equal outputs,
//   signature is valid)
// - Check that each of the transaction's inputs
//   is open for spending (i.e. hasn't been used yet as an input to
//   another transaction)

// How to store information on the block chain? Keep a set of transactions open for spending?
func (bc *BlockChain) Verify(t *Transaction) error {
	// Verify signature
	hashed, err := bytesToSign(t.Recipient, t.Inputs)
	if err != nil {
		return err
	}
	err = rsa.VerifyPKCS1v15(&t.Sender, crypto.SHA256, hashed[:], t.Signature)
	if err != nil {
		return errors.New("invalid signature")
	}

	// Verify tx inputs are keys in t.openTransactions
	for _, input := range t.Inputs {
		if val, ok := bc.openTransactions[input]; ok {
			if _, ok = val[publicKeyString(t.Sender)]; !ok {
				return errors.New("Sender does not own this transaction")
			}
		} else {
			return errors.New("Transaction not open")
		}
	}

	// Verify tx amounts are valid (inputs equal outputs)
	inputTotal := 0
	for _, inputSha := range t.Inputs {
		outputAmounts, _ := bc.openTransactions[inputSha]
		senderAmount, _ := outputAmounts[publicKeyString(t.Sender)]
		inputTotal += senderAmount
	}

	outputTotal := 0
	for _, amount := range t.Outputs {
		if amount < 0 {
			return errors.New("Cannot have negative output amount")
		}
		outputTotal += amount
	}

	if inputTotal != outputTotal {
		return fmt.Errorf("tx inputs (%d) do not match outputs (%d)", inputTotal, outputTotal)
	}

	return nil
}
