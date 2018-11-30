package main

import (
	"encoding/pem"
	"io"

	"golang.org/x/crypto/ssh"
)

func dumpOpenSSHPrivateKeyData(w io.Writer, data []byte) (err error) {
	var (
		src = pem.EncodeToMemory(&pem.Block{Type: opensshPrivateKey, Bytes: data})
		key interface{}
	)
	if key, err = ssh.ParseRawPrivateKey(src); err != nil {
		if err.Error() == "ssh: cannot decode encrypted private keys" {
			return dumpEncryptedData(w, "OpenSSH Private Key", data, map[string]string{})
		}
		return
	}
	return dumpPrivateKey(w, key, data)
}
