package main

import (
	"io/ioutil"
	"fmt"
	"test/util"
)

func main()  {
	//读取证书内容
	certByte, err := ioutil.ReadFile("static/new.p7b")
	if err != nil {
		fmt.Println("read file error")
		return
	}

	pemCert, err := util.P7bToPem(string(certByte))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(pemCert)

}
