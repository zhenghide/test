package main

import (
	"io/ioutil"
	"fmt"
	"math/big"
	"encoding/pem"
	"github.com/tjfoc/gmsm/sm2"
	x509 "github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm3"
	"crypto/ecdsa"
)

func main() {
	////读取私钥内容
	keyBytes, err := ioutil.ReadFile("static/hxdec.key")
	if err != nil {
		fmt.Println("read file error")
		return
	}
	fmt.Println("-----------------SM2私钥-----------------")
	fmt.Println(string(keyBytes))

	src := "试一试"
	r, s, err := SM2Sign(src, keyBytes)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------R--S-----------------")
	fmt.Println(r)
	fmt.Println(s)

	//读取证书内容
	certBytes, err := ioutil.ReadFile("static/hxdec.crt")
	if err != nil {
		fmt.Println("read file error")
		return
	}

	result, err := SM2VerifySign(r,s,src,string(certBytes))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(result)
}


//SM2签名
func SM2Sign(origData string, privateKeyPem []byte) (r, s *big.Int, err error) {
	//解析成sm2私钥
	block, _ := pem.Decode(privateKeyPem)
	prikey, err := sm2.ParsePKCS8PrivateKey(block.Bytes,nil)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	//fmt.Println("私钥类型:", reflect.TypeOf(prikey))

	h := sm3.New()
	h.Write([]byte(origData))
	digest := h.Sum(nil)

	r, s, err = sm2.Sign(prikey, digest)
	if err != nil {
		fmt.Println(err)
		return nil, nil, err
	}

	return
}

//SM2验签
func SM2VerifySign(r, s *big.Int, data string, pemCert string) (bool, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		fmt.Println("error")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println(err)
	}
	h := sm3.New()
	h.Write([]byte(data))
	digest := h.Sum(nil)

	//解析出来的公钥为ecdsa类型，所以需要转成sm2类型
	ecdsaPubKey := cert.PublicKey.(*ecdsa.PublicKey)
	sm2PubKey := &sm2.PublicKey{
		Curve: ecdsaPubKey.Curve,
		X:     ecdsaPubKey.X,
		Y:     ecdsaPubKey.Y,
	}
	result := sm2.Verify(sm2PubKey, digest, r, s)
	return result, nil
}
