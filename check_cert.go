package main

import (
	"io/ioutil"
	"fmt"
	x509 "github.com/tjfoc/gmsm/sm2"
	"reflect"
)

func main() {
	certPath := "static/ca_sm2.crt"
	//读取证书内容
	certBytes, err1 := ioutil.ReadFile(certPath)
	if err1 != nil {
		fmt.Println(err1)
	}

	cert, err2 := x509.ParseCertificate(certBytes)
	if err2 != nil {
		fmt.Println(err2)
	}

	fmt.Println("Subject------", cert.Subject)
	fmt.Println("PubKey_Type------", reflect.TypeOf(cert.PublicKey))

	err3 := cert.CheckSignatureFrom(cert)
	if err3 != nil {
		fmt.Println(err3)
		return
	}else {
		fmt.Println("ok")
	}

}
