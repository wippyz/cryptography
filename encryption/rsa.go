package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)
	message := "tokopedia workshop"
	pubk, err := ioutil.ReadFile("./public-key.pem")
	if err != nil {
		log.Println(err)
		return
	}
	encryptedMessage := Encrypt([]byte(message), pubk)
	log.Println("EncryptedMessage :", encryptedMessage)

	stringEncryptedMessage := base64.StdEncoding.EncodeToString(encryptedMessage)
	log.Println("EncryptedMessage :", stringEncryptedMessage)

	privk, err := ioutil.ReadFile("./private.key")
	if err != nil {
		log.Println(err)
		return
	}
	bytestringEncryptedMessage, err := base64.StdEncoding.DecodeString(stringEncryptedMessage)
	if err != nil {
		log.Println(err)
		return
	}
	decryptedMessage := Decrypt((bytestringEncryptedMessage), privk)
	log.Println("DecryptedMessage :" + decryptedMessage)
}

func Encrypt(msg []byte, bytesPublicKey []byte) []byte {

	block, _ := pem.Decode(bytesPublicKey)
	b := block.Bytes
	pub, _err := x509.ParsePKIXPublicKey(b)
	if _err != nil {
		log.Println(_err)
		return nil
	}
	hash := sha256.New()
	ciphertext, err := rsa.EncryptOAEP(hash, rand.Reader, pub.(*rsa.PublicKey), msg, nil)

	if err != nil {
		log.Println(err)
		return nil
	}
	fmt.Println("encrypting: ", string(msg))
	return ciphertext
}

func Decrypt(msg []byte, bytesPrivateKey []byte) string {

	block, _ := pem.Decode(bytesPrivateKey)
	b := block.Bytes
	priv, _err := x509.ParsePKCS1PrivateKey(b)
	if _err != nil {
		log.Println(_err)
		return ""
	}
	hash := sha256.New()
	plaintext, err := rsa.DecryptOAEP(hash, rand.Reader, priv, msg, nil)
	if err != nil {
		if _err != nil {
			log.Println(_err)
			return ""
		}
	}
	return string(plaintext)
}
