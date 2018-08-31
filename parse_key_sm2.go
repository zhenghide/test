package main

import (
	"io/ioutil"
	"fmt"
	"encoding/pem"
	//"crypto/x509"
	"reflect"
	"github.com/tjfoc/gmsm/sm2"
	x509 "github.com/tjfoc/gmsm/sm2"
	"crypto/ecdsa"
	"math/big"
)

func main() {

	//读取内容
	certBytes, err := ioutil.ReadFile("static/hxdec.crt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------读取的内容-----------------")
	fmt.Println(string(certBytes))

	block, _ := pem.Decode(certBytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("privateKey-----", cert.PublicKey)
	fmt.Println("type-----", reflect.TypeOf(cert.PublicKey))
	ecdsaPubKey := cert.PublicKey.(*ecdsa.PublicKey)
	sm2PubKey := sm2.PublicKey{
		Curve: ecdsaPubKey.Curve,
		X:     ecdsaPubKey.X,
		Y:     ecdsaPubKey.Y,
	}

	fmt.Println("sm2PubKey-----", sm2PubKey)
	fmt.Println("sm2Type-----", reflect.TypeOf(sm2PubKey))

	//解析出SM2公钥
	pubKeyStream, _ := sm2.MarshalSm2PublicKey(&sm2PubKey)
	fmt.Println("-----------------SM2公钥-----------------")
	fmt.Println(pubKeyStream)


	bigInt := &big.Int{}
	sm2PriKey := &sm2.PrivateKey{
		PublicKey: sm2PubKey,
		D:bigInt,
	}
	fmt.Println("-------------------want-------------------")
	fmt.Println(sm2PriKey)
	priKeyStream, _ := sm2.MarshalSm2PrivateKey(sm2PriKey,nil)
	fmt.Printf("%0X", priKeyStream)
	blocks := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priKeyStream,
	}
	fmt.Println("blocks:")
	fmt.Println("blocks:", blocks)
}
