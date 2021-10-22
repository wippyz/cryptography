package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	_ "math/big"
	"os"
)

func main() {

	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	checkError(err)
	pubKey := key.PublicKey
	savePrivateKey("private-key.pem", key)
	savePublicKey("public-key.pem", pubKey)

}

func savePrivateKey(fileName string, key *rsa.PrivateKey) {

	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)
	ioutil.WriteFile(fileName, privBytes, 0644)
}

func savePublicKey(fileName string, key rsa.PublicKey) {
	outFile, err := os.Create(fileName)
	checkError(err)
	defer outFile.Close()

	bytes, err := x509.MarshalPKIXPublicKey(&key)
	checkError(err)
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: bytes,
	})
	ioutil.WriteFile(fileName, []byte(pubBytes), 0644)
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
