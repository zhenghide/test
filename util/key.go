package util

import (
	"github.com/tjfoc/gmsm/sm2"
	"fmt"
	"encoding/pem"
	"bytes"
	"errors"
	"crypto/ecdsa"
)

func PriKeyToPem(sm2PriKey *sm2.PrivateKey) (pemPriKey string, err error) {
	priKeyStream, _ := sm2.MarshalSm2PrivateKey(sm2PriKey,nil)
	fmt.Println("priKeyStream:", priKeyStream)

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: priKeyStream,
	}

	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {
		return "", errors.New("Encode failed")
	}
	pemPriKey = priKey.String()

	return pemPriKey, nil
}

func DerKeyToPem(keyBytes []byte) (pemPriKey string, err error) {
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyBytes,
	}

	priKey := bytes.NewBuffer(make([]byte, 0))
	err = pem.Encode(priKey, block)
	if err != nil {

		return "", errors.New("Encode failed")
	}
	pemPriKey = priKey.String()

	return pemPriKey, nil
}

func ECKeyToSM2Key(ecKey ecdsa.PublicKey) sm2.PublicKey{
	sm2PubKey := sm2.PublicKey{
		Curve: ecKey.Curve,
		X:     ecKey.X,
		Y:     ecKey.Y,
	}

	return sm2PubKey
}