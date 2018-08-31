package util

import (
	"github.com/tjfoc/gmsm/sm4"
	"fmt"
	"crypto/cipher"
	"bytes"
	"errors"
)

//SM4加密
func SM4Encrypt(key, origData []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		fmt.Println(err)
	}
	origData = PKCS7Padding(origData)
	blockMode := cipher.NewCBCEncrypter(block, key)
	encrypted := make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted, nil
}

//SM4解密
func SM4Decrypt(key, encrypted []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := cipher.NewCBCDecrypter(block, key)
	origData := encrypted
	blockMode.CryptBlocks(origData, encrypted)
	origData, err = PKCS7UnPadding(origData)
	return origData, nil
}


func PKCS7Padding(src []byte) []byte {
	padding := sm4.BlockSize - len(src)%sm4.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > sm4.BlockSize || unpadding == 0 {
		return nil, errors.New("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, errors.New("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}
