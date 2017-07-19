package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

type Transaction struct {
	prevTxHash   []byte
	recipientKey *rsa.PublicKey
	signature    []byte
}

func (t Transaction) String() string {
	return fmt.Sprintf("<Transaction %x >", t.prevTxHash)
}

func hashTransaction(t Transaction) ([]byte, error) {
	toHash := make([]byte, 0)
	toHash = append(toHash, t.prevTxHash...)

	keyBytes, err := x509.MarshalPKIXPublicKey(t.recipientKey)
	if err != nil {
		return nil, err
	}

	toHash = append(toHash, keyBytes...)
	toHash = append(toHash, t.signature...)

	ret := make([]byte, 32)
	hash := sha256.Sum256(toHash)
	copy(ret, hash[:])
	return ret, nil
}

type Coin []Transaction

// Appends a transaction to the coin, without verifying that the
// fromKey is actually authorized to do so.
func (coin *Coin) transfer(fromKey *rsa.PrivateKey, toKey *rsa.PublicKey) error {
	keyBytes, err := x509.MarshalPKIXPublicKey(toKey)
	if err != nil {
		return err
	}

	if len(*coin) == 0 {
		// First transaction! Special case.
		fakeHash := make([]byte, 32)

		for i := 0; i < 32; i++ {
			fakeHash = append(fakeHash, 0)
		}

		toSign := append(fakeHash, keyBytes...)
		hashed := sha256.Sum256(toSign)
		signature, err := rsa.SignPKCS1v15(rand.Reader, fromKey, crypto.SHA256, hashed[:])
		if err != nil {
			return err
		}

		*coin = append(*coin, Transaction{
			prevTxHash:   fakeHash,
			recipientKey: toKey,
			signature:    signature,
		})

		return nil
	}

	prevTxHash, err := hashTransaction((*coin)[len(*coin)-1])
	if err != nil {
		return err
	}

	bytesToSign := append(prevTxHash, keyBytes...)
	hashed := sha256.Sum256(bytesToSign)
	signature, err := rsa.SignPKCS1v15(rand.Reader, fromKey, crypto.SHA256, hashed[:])
	if err != nil {
		return err
	}

	newTx := Transaction{
		prevTxHash:   prevTxHash,
		recipientKey: toKey,
		signature:    signature,
	}

	*coin = append(*coin, newTx)
	fmt.Println(*coin)
	return nil
}

func generateKey(keyname string) error {
	fmt.Println("Generating RSA private key...")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(key)
	privPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		})

	publicKey := key.PublicKey
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return err
	}

	pubPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubKeyBytes,
		},
	)
	ioutil.WriteFile(keyname, privPem, 0644)
	ioutil.WriteFile(keyname+".pub", pubPem, 0644)
	return nil
}

func loadKey(keyname string) (*rsa.PrivateKey, error) {
	privKeyPem, err := ioutil.ReadFile(keyname)
	if err != nil {
		return nil, err
	}

	privBlock, _ := pem.Decode([]byte(privKeyPem))
	if privBlock == nil {
		return nil, errors.New("failed to parse private key PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func (coin *Coin) Verify() error {

	for i := 1; i < len(*coin); i++ {
		fmt.Printf("Checking transaction %d\n", i)
		currentTransaction := (*coin)[i]
		prevTransaction := (*coin)[i-1]
		prevHash, err := hashTransaction(prevTransaction)
		if err != nil {
			return err
		}

		if !bytes.Equal(prevHash, currentTransaction.prevTxHash) {
			return errors.New("Hash values are not the same")
		}

		keyBytes, err := x509.MarshalPKIXPublicKey(currentTransaction.recipientKey)
		if err != nil {
			return err
		}

		toSign := append(prevHash, keyBytes...)
		hashed := sha256.Sum256(toSign)
		err = rsa.VerifyPKCS1v15(prevTransaction.recipientKey, crypto.SHA256, hashed[:], currentTransaction.signature)
		if err != nil {
			return err
		}
	}
	return nil
}

type Block struct {
	prevHash     [32]byte
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

func (block *Block) hashBlock() ([32]byte, error) {
	contents := make([]byte, 0)
	contents = append(contents, block.prevHash[:]...)
	nonceBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(nonceBytes, uint64(block.nonce))
	contents = append(contents, nonceBytes...)

	for _, t := range block.transactions {
		hashedTransaction, err := hashTransaction(t)
		if err != nil {
			var empty [32]byte
			return empty, err
		}
		contents = append(contents, hashedTransaction...)
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

func main() {
	var generateNewKey = flag.Bool("generate", false, "Generate a new RSA keypair")
	var keyname = flag.String("keyname", "id_rsa", "The name of the key file")
	flag.Parse()

	if *generateNewKey {
		err := generateKey(*keyname)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println("Generated key.")
	}

	key, err := loadKey(*keyname)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	message := []byte("hi there")
	hashed := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Printf("%x\n", signature)
}
