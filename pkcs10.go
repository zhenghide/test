package main

import (
	"fmt"
	"crypto/rsa"
	"crypto/ecdsa"
	"github.com/tjfoc/gmsm/sm2"
	"crypto/rand"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"crypto/x509/pkix"
	"encoding/base64"
	"bytes"
)

func main() {
	//生成DN
	dn := GetDN("zht","aisino","","","","")
	fmt.Println(dn)

	//生成证书请求
	pemPriKey, pkcs10, err := GenPkcs10("zht","aisino","","","","","","")
	if err != nil{
		fmt.Println(err)
	}
	fmt.Println("-----------------pemPrikey-----------------")
	fmt.Println(pemPriKey)
	fmt.Println("-----------------证书请求-----------------")
	fmt.Println(pkcs10)

	//从证书请求中获取信息
	sub, err := GetSubjectFromPkcs10(pkcs10)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------证书请求中信息-----------------")
	fmt.Println(sub)
}

func GetDN(name, ou, o, location, state, country string) string {
	dn := "CN=" + name
	if ou != "" {
		dn += ",OU=" + ou
	}
	if o != "" {
		dn += ",O=" + o
	}
	if location != "" {
		dn += ",L=" + location
	}
	if state != "" {
		dn += ",ST=" + state
	}
	if country != "" {
		dn += ",C=" + country
	}

	return dn
}


func GenPkcs10(name, ou, o, location, state, country, address, postcode string) (pemPrikey, pkcs10 string, err error) {
	//alg := viper.GetString("cert.alg")

	alg := "sm2"
	//生成私钥
	var rsaPrivateKey *rsa.PrivateKey
	var ecdsaPrivateKey *ecdsa.PrivateKey
	var sm2PrivateKey *sm2.PrivateKey

	switch alg {
	case "rsa1024":
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	case "rsa2048":
		rsaPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	case "ecdsa256":
		ecdsaPrivateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "sm2":
		sm2PrivateKey, err = sm2.GenerateKey()
	default:
		return "", "", fmt.Errorf("alg invalid")
	}
	if err != nil {
		return "", "", fmt.Errorf("generate private key failed: %s", err.Error())

	}

	var priKeyDerStream []byte
	switch alg {
	case "rsa1024", "rsa2048":
		priKeyDerStream = x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	case "ecdsa256":
		priKeyDerStream, err = x509.MarshalECPrivateKey(ecdsaPrivateKey)
		if err != nil {
			return "", "", fmt.Errorf("marshal privateKey failed: %s", err.Error())
		}
	case "sm2":
		priKeyDerStream, err = sm2.MarshalSm2PrivateKey(sm2PrivateKey,nil)
		if err != nil {
			return "", "", fmt.Errorf("marshal privateKey failed: %s", err.Error())
		}
	}


	//编码私钥
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priKeyDerStream,
	}
	buffer := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(buffer, block)
	if err != nil {
		return "", "", fmt.Errorf("pem encode failed: %s", err.Error())
	}
	pemPrikey = buffer.String()


	//产生证书请求
	subject := pkix.Name{
		Country:            []string{country},
		Organization:       []string{o},
		OrganizationalUnit: []string{ou},
		Locality:           []string{location},
		Province:           []string{state},
		StreetAddress:      []string{address},
		PostalCode:         []string{postcode},
		CommonName:         name,
	}

	req := &x509.CertificateRequest{
		Subject: subject,
	}
	reqsm := &sm2.CertificateRequest{
		Subject:subject,
	}

	var pkcs10DerStream []byte
	switch alg {
	case "rsa1024", "rsa2048":
		pkcs10DerStream, err = x509.CreateCertificateRequest(rand.Reader, req, rsaPrivateKey)
	case "ecdsa256":
		pkcs10DerStream, err = x509.CreateCertificateRequest(rand.Reader, req, ecdsaPrivateKey)
	case "sm2":
		pkcs10DerStream, err = sm2.CreateCertificateRequest(rand.Reader, reqsm, sm2PrivateKey)
	}
	if err != nil {
		return "", "", fmt.Errorf("CreateCertificateRequest failed: %s", err.Error())
	}

	pkcs10 = base64.StdEncoding.EncodeToString(pkcs10DerStream)

	return
}


func GetSubjectFromPkcs10(pkcs10 string) (*pkix.Name, error) {
	certReq, err := ParseCertificateRequestPlus(pkcs10)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateRequest failed: %s", err.Error())
	}
	return &certReq.Subject, nil
}

//解析证书请求升级版，引SM2中x509，支持原有国际证书请求以及SM2证书请求
func ParseCertificateRequestPlus(pkcs10 string) (*x509.CertificateRequest, error) {
	//解码base64证书请求
	pkcs10Byte, err := base64.StdEncoding.DecodeString(pkcs10)
	if err != nil {
		return nil, fmt.Errorf("decode pkcs10 failed: %s", err.Error())
	}
	certReq, err := x509.ParseCertificateRequest(pkcs10Byte)
	if err != nil {
		return nil, fmt.Errorf("ParseCertificateRequest failed: %s", err.Error())
	}
	return certReq, nil
}

