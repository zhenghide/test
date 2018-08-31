package main

import (
	"io/ioutil"
	"fmt"
	"encoding/pem"
	x509 "github.com/tjfoc/gmsm/sm2"
	//"crypto/x509"
	"test/log"
	"errors"
	"reflect"
)

func main() {
	//读取证书内容
	certBytes, err := ioutil.ReadFile("static/op.crt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------读取的内容-----------------")
	fmt.Println(string(certBytes))

	cert, err := PemCert2Cert(string(certBytes))

	//subject := cert.Subject
	//fmt.Println("Subject-----", subject)

	pubKey := cert.PublicKey
	fmt.Println("PublicKey-----", pubKey)
	fmt.Println("PublicKey Type-----", reflect.TypeOf(pubKey))

	sn, err := GetCertSn(string(certBytes))
	fmt.Println("SerialNumber", sn)

}


func PemCert2Cert(pemCert string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemCert))
	if block == nil {
		log.Log.Errorf("failed to decode pem cert")
		return nil, errors.New("failed to decode pem cert")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Log.Errorf("ParseCertificate fail: %s", err.Error())
		return nil, err
	}

	return cert, nil
}


func GetCertSn(pemCert string) (sn string, err error) {
	//解析pem证书
	cert, err := PemCert2Cert(pemCert)
	if err != nil {
		return "", fmt.Errorf("ParseCertificate fail: %s", err.Error())
	}

	snByte := cert.SerialNumber.Bytes()

	for _, v := range snByte {
		sn += fmt.Sprintf("%02X", v)
	}
	log.Log.Debugf("sn: %s", sn)

	return sn, nil

}