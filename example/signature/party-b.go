package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ping",
		})
	})
	r.POST("/payment", ReceivePayment)
	r.Run(":5000")
}

func ReceivePayment(c *gin.Context) {
	//get signature from header
	signature := c.GetHeader("signature")

	//read request body
	jsonData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"Body": "failed",
		})
		return
	}
	var jsonBody map[string]string
	json.Unmarshal(jsonData, &jsonBody)
	encryptedMessage := jsonBody["body"]

	fPriv, err := ioutil.ReadFile("b-private.key")
	checkError(err)
	decoded, err := base64.StdEncoding.DecodeString(encryptedMessage)
	checkError(err)
	decrypted := Decrypt(decoded, fPriv)
	fmt.Println("decrypted msg :", decrypted)

	pubKeyStr, err := ioutil.ReadFile("a-public.key")
	if err != nil {
		log.Fatal(err)
	}
	pubKey, err := ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("decrypt", decrypted)
	isVerified := VerifyPSS(pubKey, decrypted, signature)
	if isVerified {
		c.JSON(http.StatusOK, gin.H{
			"Body": "payment received",
		})
		return
	} else {
		c.JSON(http.StatusBadRequest, gin.H{
			"Body": "fail to validate signature",
		})
		return
	}
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

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}

func VerifyPSS(pubKey *rsa.PublicKey, msg string, base64Signature string) bool {
	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(base64Signature)

	if err != nil {
		fmt.Println("Failed to decode signature")
		return false
	}
	hashed := sha256.Sum256(message)

	errVer := rsa.VerifyPSS(pubKey, crypto.SHA256, hashed[:], bSignature, nil)
	if errVer != nil {
		fmt.Fprintf(os.Stderr, "Error from verification %s\n", errVer)
		return false
	}

	return true
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
