package main

import (
	"github.com/loganmhb/ktcoin/ktcoin"
	"fmt"
)

func main() {
	key, err := ktcoin.LoadKey("id_rsa")
	if err != nil {
		fmt.Println(err)
	} else {
		ktcoin.RunNode([]string{}, key)
	}
}
