package main

import (
	"io/ioutil"
	"fmt"

	"github.com/tjfoc/gmsm/sm2"
	"reflect"
)

func main() {

	//读取内容
	keyBytes, err := ioutil.ReadFile("static/hx.key")
	if err != nil {
		fmt.Println(err)
	}

	priKey, err := sm2.ReadPrivateKeyFromMem(keyBytes, nil)
	fmt.Println(priKey)
	fmt.Println(reflect.TypeOf(priKey))

}