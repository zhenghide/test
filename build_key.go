package main

import (
	"bytes"
	"fmt"
	"encoding/pem"
	"github.com/tjfoc/gmsm/sm2"
	"crypto/ecdsa"
	"io/ioutil"
	"math/big"
)

func main()  {
	priK := BuildPrivateKey()
	pubK := GetPubKeyFromCert()

	msg := []byte("test")
	fmt.Println("MSG---", string(msg))

	encMsg, err := sm2.Encrypt(&pubK,msg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("ENC---", string(encMsg))

	decMsg, err := sm2.Decrypt(priK, encMsg)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("DEC---", string(decMsg))

}

func BuildPriKey() *sm2.PrivateKey {
	key_front_36 := []byte{48,129,147,2,1,0,48,19,6,7,42,134,72,206,61,2,1,6,8,42,129,28,207,85,1,130,45,4,121,48,119,2,1,1,4,32}
	//key_pri_32 := []byte{145,117,188,200,239,43,147,70,93,134,180,22,245,58,17,35,229,147,170,114,5,255,125,188,122,218,20,139,53,139,140,216}
	key_pri_32 := []byte{32,145,117,188,200,239,43,147,70,93,134,180,22,245,58,17,35,229,147,170,114,5,255,125,188,122,218,20,139,53,139,140}
	key_mid_18 := []byte{160,10,6,8,42,129,28,207,85,1,130,45,161,68,3,66,0,4}
	key_pub_64 := []byte{120,102,216,80,86,85,41,198,253,183,8,33,52,109,187,220,225,156,131,185,171,18,127,13,138,73,198,251,219,197,66,144,107,242,192,231,46,186,159,25,225,130,73,192,175,242,101,29,47,131,197,197,216,134,254,221,227,68,124,3,193,35,184,159}
	//key_pub_64 := GetPubKeyFromCert()[27:]
	var buffer bytes.Buffer
	buffer.Write(key_front_36)
	buffer.Write(key_pri_32)
	buffer.Write(key_mid_18)
	buffer.Write(key_pub_64)
	priKeyStream := buffer.Bytes()
	fmt.Println(priKeyStream)

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priKeyStream,
	}
	fmt.Println("block:", block)
	priKey := bytes.NewBuffer(make([]byte, 0))
	err := pem.Encode(priKey, block)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------priKey-----------------")
	fmt.Println(priKey)
	privateKey, err := sm2.ParsePKCS8PrivateKey(priKeyStream, nil)
	return privateKey

}

func BuildPubKey() *sm2.PublicKey {
	key_front_27 := []byte{48,89,48,19,6,7,42,134,72,206,61,2,1,6,8,42,129,28,207,85,1,130,45,3,66,0,4}
	key_pub_64 := []byte{120,102,216,80,86,85,41,198,253,183,8,33,52,109,187,220,225,156,131,185,171,18,127,13,138,73,198,251,219,197,66,144,107,242,192,231,46,186,159,25,225,130,73,192,175,242,101,29,47,131,197,197,216,134,254,221,227,68,124,3,193,35,184,159}
	var buffer bytes.Buffer
	buffer.Write(key_front_27)
	buffer.Write(key_pub_64)
	pubKeyStream := buffer.Bytes()
	fmt.Println("-----------------pubKeyStream---------------------")
	fmt.Println(pubKeyStream)

	pubKey, err := sm2.ParseSm2PublicKey(pubKeyStream)
	if err != nil {
		fmt.Println(err)
	}

	return pubKey
}


func GetPubKeyFromCert() sm2.PublicKey {
	certBytes, err := ioutil.ReadFile("static/hxdec.crt")
	if err != nil {
		fmt.Println(err)
	}

	block, _ := pem.Decode(certBytes)
	if block == nil {
		fmt.Println("block is nil")
	}

	cert, err := sm2.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	ecdsaPubKey := cert.PublicKey.(*ecdsa.PublicKey)
	sm2PubKey := sm2.PublicKey{
		Curve: ecdsaPubKey.Curve,
		X:     ecdsaPubKey.X,
		Y:     ecdsaPubKey.Y,
	}

	return sm2PubKey
}

func BuildPrivateKey() *sm2.PrivateKey{
	keyPri32 := []byte{145,117,188,200,239,43,147,70,93,134,180,22,245,58,17,35,229,147,170,114,5,255,125,188,122,218,20,139,53,139,140,216}

	sm2PubKey := GetPubKeyFromCert()
	d := new(big.Int).SetBytes(keyPri32)

	//c := sm2.P256Sm2()
	//priKey := new(sm2.PrivateKey)
	//priKey.PublicKey.Curve = c
	//priKey.D = d
	//priKey.PublicKey.X, priKey.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

	priKey := &sm2.PrivateKey{
		PublicKey: sm2PubKey,
		D: d,
	}

	priKeyStream, err := sm2.MarshalSm2PrivateKey(priKey,nil)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------priKeyStream---------------")
	fmt.Println(priKeyStream)
	return priKey
}
