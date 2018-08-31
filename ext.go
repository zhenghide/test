package main

import (
	"io/ioutil"
	"fmt"
)

func main()  {
	//读取证书内容
	certBytes, err := ioutil.ReadFile("static/new.crt")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------读取的内容-----------------")
	fmt.Println(string(certBytes))

	//ext, err := utils.GetSelfDefineCertExt(string(certBytes))
	//if err != nil {
	//	fmt.Println(err)
	//}
	//fmt.Println("EXT-----", ext)
}
