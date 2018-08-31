package util

import (
	"strconv"
	"time"
	"path/filepath"
	"io/ioutil"
	"fmt"
	"os/exec"
)

//把p7b格式证书转换为pem格式证书
func P7bToPem(p7bCert string) (pemCert string, err error) {
	t := strconv.FormatInt(time.Now().UnixNano(), 10)
	inFile := filepath.Join("/tmp", "tmpCert"+t+".p7b")
	outFile := filepath.Join("/tmp", "tmpCert"+t+".cer")

	err = ioutil.WriteFile(inFile, []byte(p7bCert), 0666)
	if err != nil {
		return "", fmt.Errorf("WriteFile %s fail: %s", inFile, err.Error())
	}

	arg := "openssl pkcs7" + " -print_certs -in " + inFile + " -out " + outFile
	cmd := exec.Command("/bin/sh", "-c", arg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	inbyte, err := ioutil.ReadFile(outFile)
	if err != nil {
		return "", fmt.Errorf("ReadFile %s fail: %s", outFile, err.Error())
	}
	pemCert = string(inbyte)

	//删除临时文件
	arg = "rm -rf " + inFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	arg = "rm -rf " + outFile
	cmd = exec.Command("/bin/sh", "-c", arg)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("exe cmd %s fail: %s", arg, string(out))
	}

	return
}

