package main

import (
	"github.com/loganmhb/ktcoin/ktcoin"
	"fmt"
	"flag"
)

func main() {
	flag.Parse()
	key, err := ktcoin.LoadKey("id_rsa")
	if err != nil {
		fmt.Println(err)
	} else {
		ktcoin.RunNode([]string{flag.Arg(0), flag.Arg(1)}, key)
	}
}
