package main

import (
	"io/ioutil"
	"fmt"
	"encoding/pem"
	"github.com/tjfoc/gmsm/sm2"
	"crypto/ecdsa"
)

func main(){
	certBytes, err := ioutil.ReadFile("static/enc.crt")
	if err != nil {
		fmt.Println(err)
	}

	certBlock, _ := pem.Decode(certBytes)
	if certBlock == nil {
		fmt.Println("certBlock is nil")
	}
	cert, err := sm2.ParseCertificate(certBlock.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	ecdsaPubKey := cert.PublicKey.(*ecdsa.PublicKey)
	sm2PubKey := sm2.PublicKey{
		Curve: ecdsaPubKey.Curve,
		X:     ecdsaPubKey.X,
		Y:     ecdsaPubKey.Y,
	}

	keyBytes, err := ioutil.ReadFile("static/enc.key")
	if err != nil {
		fmt.Println(err)
	}

	keyBlock, _ := pem.Decode(keyBytes)
	if keyBlock == nil {
		fmt.Println("keyBlock is nil")
	}

	privateKey, err := sm2.ParsePKCS8PrivateKey(keyBlock.Bytes, nil)
	if err != nil {
		fmt.Println(err)
	}

	msg := []byte("test")

	encMsg, err := sm2.Encrypt(&sm2PubKey,msg)
	fmt.Println("ENC---", string(encMsg))

	decMsg, err := sm2.Decrypt(privateKey, encMsg)
	fmt.Println("DEC---", string(decMsg))
}
