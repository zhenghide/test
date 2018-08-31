package main

import (
	"fmt"
	"test/util"
)

func main() {

	msg := []byte("abcdefg")
	key := []byte("12345678")

	fmt.Println("-----------------原文-----------------")
	fmt.Println(msg)
	fmt.Println(string(msg))

	//rc4加密
	enc,_ := util.RC4Crypt(key,msg)
	fmt.Println("-----------------RC4加密后密文-----------------")
	fmt.Println(enc)
	fmt.Println(string(enc))

	//rc4解密
	dec,_ := util.RC4Crypt(key,enc)
	fmt.Println("-----------------RC4解密后明文-----------------")
	fmt.Println(dec)
	fmt.Println(string(dec))
}


