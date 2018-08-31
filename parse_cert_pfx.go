package main

import (
	"fmt"
	"strconv"
	"time"
	"path/filepath"
	"os/exec"
	"io/ioutil"
	"test/log"
)

func main() {
	//解析操作员证书pfx格式文件得到证书和私钥
	pfxFile := "static/40server-opt.pfx"
	pwd := "111111"
	operatorPemCert, operatorPemPriKey, err := ParsePfx(pfxFile, pwd)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("-----------------Pem证书-----------------")
	fmt.Println(string(operatorPemCert))
	fmt.Println("-----------------私钥-----------------")
	fmt.Println(string(operatorPemPriKey))

	sn, err := GetCertSn(string(operatorPemCert))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("SN---", sn)
}

//解析pfx文件得到pem格式的证书和私钥
func ParsePfx(pfxFile, pwd string) (pemCert, pemPrivateKey []byte, err error) {
	t := strconv.FormatInt(time.Now().UnixNano(), 10)
	outCertFile := filepath.Join("/tmp", "tmpCert"+t+".cer")
	outEncPrikeyFile := filepath.Join("/tmp", "tmpEncPrikey"+t+".pem")
	outPrikeyFile := filepath.Join("/tmp", "tmpPrikey"+t+".pem")

	//解析出证书
	arg := "openssl pkcs12 -clcerts -nokeys -in " + pfxFile + " -passin pass:" + pwd + " -out " + outCertFile
	cmd := exec.Command("/bin/sh", "-c", arg)
	log.Log.Debugf("arg: %s", arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	//解析出密文私钥
	arg = "openssl pkcs12" + " -nocerts -in " + pfxFile + " -passin pass:" + pwd + " -passout pass:123456" + " -out " + outEncPrikeyFile
	log.Log.Debugf("arg: %s", arg)
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	//去掉pem私钥的密码
	arg = "openssl rsa" + " -in " + outEncPrikeyFile + " -passin pass:123456" + " -out " + outPrikeyFile
	log.Log.Debugf("arg: %s", arg)
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	pemCert, err = ioutil.ReadFile(outCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("ReadFile %s fail: %s", outCertFile, err.Error())
	}

	pemPrivateKey, err = ioutil.ReadFile(outPrikeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("ReadFile %s fail: %s", outPrikeyFile, err.Error())
	}

	//删除临时文件
	arg = "rm -rf " + outCertFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	arg = "rm -rf " + outEncPrikeyFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	arg = "rm -rf " + outPrikeyFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	return
}
