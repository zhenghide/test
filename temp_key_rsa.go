package main

import (
	"fmt"
	"encoding/base64"
	"crypto/rsa"
	"crypto/rand"
	"math/big"
	"encoding/asn1"
	"errors"
	"crypto/x509"
	"encoding/pem"
)

func main() {
	var tempPriKey *rsa.PrivateKey
	var err error
	tempPriKey, err = rsa.GenerateKey(rand.Reader,1024)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------RSA私钥-----------------")
	fmt.Println(tempPriKey)

	priKeyStream := x509.MarshalPKCS1PrivateKey(tempPriKey)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: priKeyStream,
	}
	fmt.Println("-----------------block-----------------")
	fmt.Println(block)
	//file, err := os.Create("tmp/tmpPriKey.key")
	//if err != nil {
	//	fmt.Println(err)
	//}
	//err = pem.Encode(file, block)
	//if err != nil {
	//	fmt.Println(err)
	//}

	//解析出RSA公钥
	pubKeyStream, _ := MarshalPublicKey(&tempPriKey.PublicKey)
	fmt.Println("-----------------RSA公钥-----------------")
	fmt.Println(pubKeyStream)

	//编码RSA公钥
	tempPubKey := base64.StdEncoding.EncodeToString(pubKeyStream)
	fmt.Println("-----------------BASE64-----------------")
	fmt.Println(tempPubKey)
	
}

// pkcs1PublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type pkcs1PublicKey struct {
	N *big.Int
	E int
}

// MarshalPublicKey serialises a public key to DER-encoded format.
func MarshalPublicKey(pub interface{}) ([]byte, error) {
	var publicKeyBytes []byte
	var err error

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(pkcs1PublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("x509: only RSA public keys supported")
	}

	/*	bitString := asn1.BitString{
			Bytes:     publicKeyBytes,
			BitLength: 8 * len(publicKeyBytes),
		}

		ret, _ := asn1.Marshal(bitString)*/
	return publicKeyBytes, nil
}
