package util

import (
	"io/ioutil"
	"fmt"
	"encoding/pem"
)

func ReadFromPem(path string) []byte {
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println(err)
	}

	//解码私钥
	block, _ := pem.Decode(bytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	return block.Bytes
}

