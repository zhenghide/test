package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"crypto/rand"
	"encoding/pem"
	"bytes"
	"crypto/x509"
	"crypto/md5"
	"test/util"
	"errors"
)

var SignCertBase64 = "MIAGCSqGSIb3DQEHAqCAMIACAQExADCABgkqhkiG9w0BBwEAAKCAMIICNzCCAdugAwIBAgIIEAAAAAAQu6AwDAYIKoEcz1UBg3UFADAfMQswCQYDVQQGEwJDTjEQMA4GA1UEAwwHY2EtdGVzdDAeFw0xODA4MTYwMjE4MzBaFw0yMzA4MTUwMjE4MzBaMB8xDzANBgNVBAsMBmFpc2lubzEMMAoGA1UEAwwDemh0MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEXtGY6ZknQHFNzlmsEc8BxkOiAzkcqfgOvcYSbtDn+WtaEKkqnSHhbSh4YuxKBIgEFEgNNTwf0L7PZr/n2SEYeaOB/jCB+zAdBgNVHQ4EFgQUdWhchwo5sLCA/NuwzPQnKE9Q6CIwHwYDVR0jBBgwFoAU1NekO2mKPuxPlJnjkFfeZ+Gpjv0wCwYDVR0PBAQDAgbAMIGdBgNVHR8EgZUwgZIwS6AkoCKGIGxkYXA6Ly86bnVsbC9jbj1mdWxsQ3JsLmNybCxudWxsoiOkITAfMQswCQYDVQQGEwJDTjEQMA4GA1UEAwwHY2EtdGVzdDBDoBygGoYYbnVsbDEwMDAwMDAwMDAxMEJCMDAuY3JsoiOkITAfMQswCQYDVQQGEwJDTjEQMA4GA1UEAwwHY2EtdGVzdDAMBgNVHRMEBTADAQEAMAwGCCqBHM9VAYN1BQADSAAwRQIhAL28ZUTcKGJTqsRo2zp9RHPpSMi7eek+UfzQPL5zMoC+AiA771BH8EzxzP7wDpUhZZ1yDqez5Syp935ZF0wfGbFvcAAAMQAAAAAAAAA="
var DecCertBase64 = "MIAGCSqGSIb3DQEHAqCAMIACAQExADCABgkqhkiG9w0BBwEAAKCAMIICNzCCAdugAwIBAgIIEAAAAAAQu58wDAYIKoEcz1UBg3UFADAfMQswCQYDVQQGEwJDTjEQMA4GA1UEAwwHY2EtdGVzdDAeFw0xODA4MTYwMjE4MzBaFw0yMzA4MTUwMjE4MzBaMB8xDzANBgNVBAsMBmFpc2lubzEMMAoGA1UEAwwDemh0MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEeGbYUFZVKcb9twghNG273OGcg7mrEn8NiknG+9vFQpBr8sDnLrqfGeGCScCv8mUdL4PFxdiG/t3jRHwDwSO4n6OB/jCB+zAdBgNVHQ4EFgQUNEiTwhMuPeg9972p+BaftTba03AwHwYDVR0jBBgwFoAU1NekO2mKPuxPlJnjkFfeZ+Gpjv0wCwYDVR0PBAQDAgQwMIGdBgNVHR8EgZUwgZIwS6AkoCKGIGxkYXA6Ly86bnVsbC9jbj1mdWxsQ3JsLmNybCxudWxsoiOkITAfMQswCQYDVQQGEwJDTjEQMA4GA1UEAwwHY2EtdGVzdDBDoBygGoYYbnVsbDEwMDAwMDAwMDAxMGJiMDAuY3JsoiOkITAfMQswCQYDVQQGEwJDTjEQMA4GA1UEAwwHY2EtdGVzdDAMBgNVHRMEBTADAQEAMAwGCCqBHM9VAYN1BQADSAAwRQIgZ+IpWh2xaV1NmrL2nUJ4WxuPxD25yxWWb+/Bvwf4kgcCIQDazbcA5Vms95mTe/TJPZZZdivsDiwOPQOgfLDDd77X0QAAMQAAAAAAAAA="
var EncryptedPrivateKeyBase64 = "XjboGNZGfuqydVOAiYu8ralMUuj7ILnBGrjbjuQVO02wZnYAIcI+nn+ovH5khxGgwJfzZZumY/v10MNW34qoJw=="
var EncryptedSessionKeyBase64 = "sitIyVDGuzWl2uRega/TB4ujnnxoGI6CRJIEZLOR6AuXO8+HYMFRSEhC2A/RgyiSDe7xGCV8qELpt29ln1bmWV5CL8hDOReECrWTv8L0fFA8i4PcukC7rbzV97NDdHCJbdgH5/GHH6SQZMDmvUBQaq6/V7GLlQm+ynG1w3f87Vc="
var PriKey = "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgBViTJF2ZbDZ7dGfjwbISVaxXSJ7nxjgAA8Sely+0ISigCgYIKoEcz1UBgi2hRANCAARe0ZjpmSdAcU3OWawRzwHGQ6IDORyp+A69xhJu0Of5a1oQqSqdIeFtKHhi7EoEiAQUSA01PB/Qvs9mv+fZIRh5"

func main()  {
	tmpPriKey, _ := readTmpPriKey()
	pemPriKey, err := UnpackEnvelop(EncryptedPrivateKeyBase64,EncryptedSessionKeyBase64,tmpPriKey)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pemPriKey)

	pemCert,err := convertCert(DecCertBase64)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pemCert)


}


func UnpackEnvelop(EncryptedPrivateKeyBase64, EncryptedSessionKeyBase64 string, tmpPrivateKey *rsa.PrivateKey) (priKeyBytes []byte, err error) {
	//私钥密文base64解码
	EncryptedPrivateKey, err := base64.StdEncoding.DecodeString(EncryptedPrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("EncryptedPrivateKey base64 decode failed: %s", err.Error())
	}

	//会话密钥base64解码
	EncryptedSessionKey, err := base64.StdEncoding.DecodeString(EncryptedSessionKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("EncryptedSessionKey base64 decode failed: %s", err.Error())
	}

	//翻转加密的会话密钥
	Reverse(EncryptedSessionKey)

	//解密会话密钥
	sessionKey, err := rsa.DecryptPKCS1v15(rand.Reader, tmpPrivateKey, EncryptedSessionKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt session key failed: %s", err.Error())
	}

	//会话密钥派生rc4密钥
	h := md5.New()
	h.Write(sessionKey)
	rc4key := h.Sum(nil)

	//rc4密钥解密私钥
	dist, err := util.RC4Crypt(rc4key, EncryptedPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key failed: %s", err.Error())
	}


	return dist[28:60], nil
}


func Reverse(s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func readTmpPriKey() (*rsa.PrivateKey, error) {
	keyBytes := util.ReadFromPem("tmp/tmpPriKey.key")

	tmpPriKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, errors.New("ParsePKCS1PrivateKey failed")
	}
	return tmpPriKey, nil
}


//把ca返回的base64编码的p7b证书转换为pem编码的证书
func convertCert(cert string) (pemCert string, err error) {
	//签名证书base64解码
	decodeBytes, err := base64.StdEncoding.DecodeString(cert)
	if err != nil {
		return "", fmt.Errorf("p7b cert base64 decode failed: %s", err.Error())
	}
	//签名证书pem编码
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: decodeBytes,
	}
	sigcert := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(sigcert, block)
	if err != nil {
		return "", fmt.Errorf("p7b cert pem encode failed: %s", err.Error())
	}

	//把p7b证书转换成pem证书
	pemCert, err = util.P7bToPem(sigcert.String())
	if err != nil {
		return "", fmt.Errorf("P7b2Pem failed: %s", err.Error())
	}

	return
}
