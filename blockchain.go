package ktcoin

import (
	"crypto/sha256"
	"encoding/binary"
)

type Block struct {
	prevHash     SHA
	nonce        int
	transactions []Transaction
}

type BlockChain struct {
	blocks []Block
}

func NewBlockChain() BlockChain {
	genesisHash := sha256.Sum256([]byte("genesis"))
	blocks := make([]Block, 0)
	blocks = append(blocks, Block{genesisHash, 0, make([]Transaction, 0)})
	return BlockChain{blocks}
}

func (block *Block) hashBlock() (SHA, error) {
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
	mostRecentBlock := bc.blocks[len(bc.blocks)-1]
	prevHash, err := mostRecentBlock.hashBlock()
	if err != nil {
		return err
	}
	nonce := 0
	newBlock := Block{prevHash, nonce, transactions}
	hashedBlock, err := newBlock.hashBlock()
	if err != nil {
		return err
	}
	for hashedBlock[0] != 0 {
		newBlock.nonce++
		hashedBlock, err = newBlock.hashBlock()
		if err != nil {
			return err
		}
	}
	bc.blocks = append(bc.blocks, newBlock)
	return nil
}
