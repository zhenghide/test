package main

import (
	"io/ioutil"
	"fmt"
	"encoding/pem"
	//"crypto/x509"
	x509 "github.com/tjfoc/gmsm/sm2"
	"reflect"
)

func main() {

	//读取内容
	keyBytes, err := ioutil.ReadFile("static/rsa.key")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------读取的内容-----------------")
	fmt.Println(string(keyBytes))

	//解码私钥
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("privateKey-----", privateKey)
	fmt.Println("typr-----", reflect.TypeOf(privateKey))

}