package ktcoin

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// A Block consists of the previous block's hash, the list of
// transactions it enacts, and a nonce.  For a block to be valid, the
// SHA256 hash must have sufficient leading zeroes to satisfy the
// proof of work property.
type Block struct {
	prevHash     SHA
	nonce        int
	transactions []Transaction
}

type BlockChain struct {
	blocks           []Block
	openTransactions map[SHA]map[*rsa.PublicKey]int
}

func NewBlockChain() BlockChain {
	genesisHash := sha256.Sum256([]byte("genesis"))
	blocks := make([]Block, 0)
	blocks = append(blocks, Block{genesisHash, 0, make([]Transaction, 0)})
	openTransactions := make(map[SHA]map[*rsa.PublicKey]int)
	return BlockChain{
		blocks,
		openTransactions,
	}
}

func (block *Block) Hash() (SHA, error) {
	contents := make([]byte, 0)
	contents = append(contents, block.prevHash[:]...)
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, uint64(block.nonce))
	contents = append(contents, nonceBytes...)

	for _, t := range block.transactions {
		hashedTransaction, err := t.Hash()
		if err != nil {
			var empty SHA
			return empty, err
		}
		contents = append(contents, hashedTransaction[:]...)
	}

	hash := sha256.Sum256(contents)
	return hash, nil
}

func (bc *BlockChain) addNextBlock(transactions []Transaction) error {
	// Verify transactions
	for i, t := range transactions {
		if i == 0 {
			// Special case: money from nothing
			outputTotal := 0
			for _, v := range t.outputs {
				outputTotal += v
			}
			if outputTotal != 25 {
				return errors.New("Invalid genesis transaction: does not create 25 coins")
			}
		} else {
			err := bc.Verify(&t)
			if err != nil {
				return err
			}
		}
	}

	// Look for the magic hash value
	mostRecentBlock := bc.blocks[len(bc.blocks)-1]
	prevHash, err := mostRecentBlock.Hash()
	if err != nil {
		return err
	}
	nonce := 0
	newBlock := Block{prevHash, nonce, transactions}
	hashedBlock, err := newBlock.Hash()
	if err != nil {
		return err
	}
	for hashedBlock[0] != 0 {
		newBlock.nonce++
		hashedBlock, err = newBlock.Hash()
		if err != nil {
			return err
		}
	}

	// Append the block to the chain
	bc.blocks = append(bc.blocks, newBlock)

	for _, transaction := range transactions {
		for _, input := range transaction.inputs {
			delete(bc.openTransactions[input], transaction.sender)
		}
		hashedTransaction, err := transaction.Hash()
		if err != nil {
			return err
		}

		bc.openTransactions[hashedTransaction] = transaction.outputs
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
	hashed, err := bytesToSign(t.recipient, t.inputs)
	if err != nil {
		return err
	}
	err = rsa.VerifyPKCS1v15(t.sender, crypto.SHA256, hashed[:], t.signature)
	if err != nil {
		return errors.New("invalid signature")
	}

	// Verify tx inputs are keys in t.openTransactions
	for _, input := range t.inputs {
		if val, ok := bc.openTransactions[input]; ok {
			if _, ok = val[t.sender]; !ok {
				return errors.New("Sender does not own this transaction")
			}
		} else {
			return errors.New("Transaction not open")
		}
	}

	// Verify tx amounts are valid (inputs equal outputs)
	inputTotal := 0
	for _, inputSha := range t.inputs {
		outputAmounts, _ := bc.openTransactions[inputSha]
		senderAmount, _ := outputAmounts[t.sender]
		inputTotal += senderAmount
	}

	outputTotal := 0
	for _, amount := range t.outputs {
		outputTotal += amount
	}

	if inputTotal != outputTotal {
		return errors.New("tx inputs do not match outputs")
	}

	return nil
}
