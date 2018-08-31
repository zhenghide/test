package main

import (
	"fmt"
	"test/util"
)

func main() {
	msg := []byte("abcd")
	key := []byte("123456789abcdefg")

	enMsg, err := util.SM4Encrypt(key,msg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------SM4加密后密文-----------------")
	fmt.Println(enMsg)
	fmt.Println(string(enMsg))

	deMsg,_ := util.SM4Decrypt(key,enMsg)
	fmt.Println("-----------------SM4解密后明文-----------------")
	fmt.Println(deMsg)
	fmt.Println(string(deMsg))

}
