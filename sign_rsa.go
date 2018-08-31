package main

import (
	"io/ioutil"
	"fmt"
	"crypto"
	"encoding/pem"
	"crypto/x509"
	"crypto/rsa"
	"encoding/base64"
	"reflect"
)

func main() {
	//读取私钥内容
	keyBytes, err := ioutil.ReadFile("static/rsa.key")
	if err != nil {
		fmt.Println("read file error")
		return
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(string(keyBytes))

	src := "试一试"
	s, err := RsaSign(src, keyBytes, crypto.SHA256)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------S-----------------")
	fmt.Println(s)


	////读取证书内容
	certBytes, err := ioutil.ReadFile("static/rsa.crt")
	if err != nil {
		fmt.Println("read file error")
		return
	}

	fmt.Println("-----------------SM2证书-----------------")
	fmt.Println(string(certBytes))

	e := RsaVerifySign(s,src,string(certBytes),crypto.SHA256)
	if e != nil {
		fmt.Println(e)
	}
	fmt.Println("pass")

}


func RsaSign(origData string, privateKeyPem []byte, hash crypto.Hash) (sig string, err error) {
	//解析成RSA私钥
	block, _ := pem.Decode(privateKeyPem)
	prikey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	h := hash.New()
	h.Write([]byte(origData))
	digest := h.Sum(nil)

	s, err := rsa.SignPKCS1v15(nil, prikey, hash, digest)
	if err != nil {
		fmt.Println(err)
	}
	sig = base64.StdEncoding.EncodeToString(s)
	return
}

func RsaVerifySign(signBase64 string, data string, pemCert string, hash crypto.Hash) error {
	//base64解码
	sign, err := base64.StdEncoding.DecodeString(signBase64)
	if err != nil {
		fmt.Println(err)
	}

	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		fmt.Println(err)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}

	h := hash.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	testPubKey := cert.PublicKey
	fmt.Println("公钥类型：", reflect.TypeOf(testPubKey))

	rsaPubKey := cert.PublicKey.(*rsa.PublicKey)
	return rsa.VerifyPKCS1v15(rsaPubKey, hash, digest, sign)
}
