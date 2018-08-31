package main

import (
	"github.com/tjfoc/gmsm/sm2"
	"fmt"
	"encoding/base64"
	"test/util"
)

func main() {
	tempPriKey, err := sm2.GenerateKey()
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(tempPriKey)
	fmt.Println(&tempPriKey.PublicKey)

	pemPriKey, err := util.PriKeyToPem(tempPriKey)
	fmt.Println("-----------------SM2私钥PEM-----------------")
	fmt.Println(pemPriKey)

	//解析出SM2公钥
	pubKeyStream, _ := sm2.MarshalPKIXPublicKey(&tempPriKey.PublicKey)
	fmt.Println("-----------------SM2公钥-----------------")
	fmt.Println(pubKeyStream)


	//编码SM2公钥
	tempPubKey := base64.StdEncoding.EncodeToString(pubKeyStream)
	fmt.Println("-----------------BASE64-----------------")
	fmt.Println(tempPubKey)
	
}
