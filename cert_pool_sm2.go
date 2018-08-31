package main

import (
	//"crypto/x509"
	//"crypto/tls"
	"fmt"
	"github.com/tjfoc/gmhttp"
	"github.com/tjfoc/gmsm/sm2"
	tls "github.com/tjfoc/gmtls"
)

var x509CaCrt = []byte(`
-----BEGIN CERTIFICATE-----
MIIBdzCCAR2gAwIBAgIBATAKBggqhkjOPQQDAjAcMRowGAYDVQQDDBFyb290Y2Eu
YWlzaW5vLmNvbTAeFw0xODA0MTMwNTQxNDBaFw0zODA0MDgwNTQxNDBaMBwxGjAY
BgNVBAMMEXJvb3RjYS5haXNpbm8uY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD
QgAE45TORIzORepSuNRbVUBBtMXyY8BnF5fOxit5ENdnsLg4eH1nbZVhfFcF/mCD
ARpF8cn5KyruAxwgAWPxE6H8YqNQME4wHQYDVR0OBBYEFOIm83H+vQHxy7cES/o6
jY6cBE2KMB8GA1UdIwQYMBaAFOIm83H+vQHxy7cES/o6jY6cBE2KMAwGA1UdEwQF
MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgQXn850Ac43xAOJP8u5uIwzEDmMqqGjiU
t7QrD/Oi/zkCIQCtCoZc3ZCkwF6lO0SkTSdZPVkffWm3LOeQtBL524CFEA==
-----END CERTIFICATE-----
`)

var x509ClientCertPath = "e:/test/tls/fabricMgt.crt"
var x509ClientKeyPath = "e:/test/tls/fabricMgt_sk"
var serverName = ""

func main() {
	pool := sm2.NewCertPool()

	pool.AppendCertsFromPEM(x509CaCrt)
	clientCrt, err := tls.LoadX509KeyPair(x509ClientCertPath, x509ClientKeyPath)
	if err != nil {
		fmt.Errorf("load tls key pair failed: %s", err.Error())
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:      pool,
			Certificates: []tls.Certificate{clientCrt},
			ServerName:   serverName,
		},
		DisableKeepAlives:     true,
	}
	client := &http.Client{Transport: tr}
	fmt.Println(client)
}