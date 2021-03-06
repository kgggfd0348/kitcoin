package ktcoin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type SHA [32]byte

func (sha *SHA) String() string {
	return fmt.Sprintf("%x", *sha)
}

func GenerateKey(keyname string) error {
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

func LoadKey(keyname string) (*rsa.PrivateKey, error) {
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

func LoadPublicKey(keyname string) (*rsa.PublicKey, error) {
	pubKeyPem, err := ioutil.ReadFile(keyname)
	if err != nil {
		return nil, err
	}

	pubBlock, _ := pem.Decode([]byte(pubKeyPem))
	if pubBlock == nil {
		return nil, errors.New("failed to parse public key PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return nil, err
	}

	switch pubKey.(type) {
	case *rsa.PublicKey:
		return pubKey.(*rsa.PublicKey), nil
	default:
		return nil, errors.New("invalid key format")
	}
}

func publicKeyString(key rsa.PublicKey) string {
	s, err := x509.MarshalPKIXPublicKey(&key)
	if err != nil {
		fmt.Println("Unexpected error unmarshalling:", err)
		panic("unreachable code")
	}
	return hex.EncodeToString(s)
}

// func (coin *Coin) Verify() error {

// 	for i := 1; i < len(*coin); i++ {
// 		fmt.Printf("Checking transaction %d\n", i)
// 		currentTransaction := (*coin)[i]
// 		prevTransaction := (*coin)[i-1]
// 		prevHash, err := hashTransaction(prevTransaction)
// 		if err != nil {
// 			return err
// 		}

// 		if !bytes.Equal(prevHash, currentTransaction.prevTxHash) {
// 			return errors.New("Hash values are not the same")
// 		}

// 		keyBytes, err := x509.MarshalPKIXPublicKey(currentTransaction.recipientKey)
// 		if err != nil {
// 			return err
// 		}

// 		toSign := append(prevHash, keyBytes...)
// 		hashed := sha256.Sum256(toSign)
// 		err = rsa.VerifyPKCS1v15(prevTransaction.recipientKey, crypto.SHA256, hashed[:], currentTransaction.signature)
// 		if err != nil {
// 			return err
// 		}
// 	}
// 	return nil
// }
