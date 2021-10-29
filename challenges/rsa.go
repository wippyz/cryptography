package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	_ "crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	_ "math/big"
	"os"
	"strings"
)

func IsFileExists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func main() {
	message := ""
	fPub, err := ioutil.ReadFile("public.key")

	checkError(err)
	encrypted := base64.StdEncoding.EncodeToString(Encrypt([]byte(message), fPub))
	encrypted = strings.TrimSpace(encrypted)
	fmt.Println("encrypted msg: ", encrypted)
	fPriv, err := ioutil.ReadFile("private.key")
	checkError(err)
	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	checkError(err)
	decrypted := Decrypt(decoded, fPriv)
	fmt.Println("decrypted msg: ", decrypted)

}

func Encrypt(msg []byte, bytesPublicKey []byte) []byte {

	block, _ := pem.Decode(bytesPublicKey)
	b := block.Bytes
	pub, _err := x509.ParsePKIXPublicKey(b)
	checkError(_err)
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub.(*rsa.PublicKey), msg, nil)

	if err != nil {
		checkError(err)
	}
	return ciphertext
}

func Decrypt(msg []byte, bytesPrivateKey []byte) string {

	block, _ := pem.Decode(bytesPrivateKey)
	b := block.Bytes
	priv, _err := x509.ParsePKCS1PrivateKey(b)
	checkError(_err)
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, msg, nil)
	if err != nil {
		checkError(err)
	}
	return string(plaintext)
}

func DecryptSHA1(msg []byte, bytesPrivateKey []byte) string {

	block, _ := pem.Decode(bytesPrivateKey)
	b := block.Bytes
	priv, _err := x509.ParsePKCS1PrivateKey(b)
	checkError(_err)
	hash := sha1.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, msg, nil)
	if err != nil {
		checkError(err)
	}
	return string(plaintext)
}

func DecryptWithPrivateKey(ciphertext []byte, priv *rsa.PrivateKey) []byte {
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, ciphertext, nil)
	if err != nil {
		checkError(err)
	}
	return plaintext
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
