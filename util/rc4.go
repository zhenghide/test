package util

import (
	"crypto/rc4"
	"fmt"
)

func RC4Crypt(key []byte, src []byte) (dist []byte, err error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("NewCipher failed: %s", err.Error())
	}

	dist = make([]byte, len(src))
	c.XORKeyStream(dist, src)

	return dist, nil
}
