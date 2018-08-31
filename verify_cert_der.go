package main

import (
	"io/ioutil"
	"fmt"
	//"crypto/x509"
	"time"
	x509 "github.com/tjfoc/gmsm/sm2"
)

func main() {
	//读取证书内容
	orgCertBytes, err := ioutil.ReadFile("static/ca_sm2.cer")
	if err!= nil{
		fmt.Println(err)
	}

	caCertBytes, err := ioutil.ReadFile("static/ca_sm2.cer")
	if err!= nil{
		fmt.Println(err)
	}
	//验证证书链
	chain := make([][]byte,1)
	chain[0] = caCertBytes
	err = VerifyCertDer(orgCertBytes, chain)
	if err != nil {
		fmt.Println(err)
		return
	}else {
		fmt.Println("ok")
	}
}

//升级版验证证书链方法
func VerifyCertDer(cert []byte, certChain [][]byte) error {

	c, err := x509.ParseCertificate(cert)
	if err != nil {
		return fmt.Errorf("parse x509 cert fail: %s", err.Error())
	}

	var cas []*x509.Certificate
	for _, caCert := range certChain {
		ca, err := x509.ParseCertificate(caCert)
		if err != nil {
			return fmt.Errorf("parse x509 cacert fail: %s", err.Error())
		}

		cas = append(cas, ca)
	}

	return VerifyX509CertDer(c, cas)
}

func VerifyX509CertDer(c *x509.Certificate, cas []*x509.Certificate) error {
	now := time.Now()
	if now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return fmt.Errorf("certificate has expired or is not yet valid")
	}

	var err error
	for _, ca := range cas {
		err = c.CheckSignatureFrom(ca)
		if err == nil {
			err = ca.CheckSignatureFrom(ca)
			if err == nil { //root ca
				return nil
			} else {
				return VerifyX509CertDer(ca, cas)
			}
		}
	}
	return err
}
