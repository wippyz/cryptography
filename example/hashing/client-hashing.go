package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	// get profile by email
	userEmail := "fahrur@tokopedia.com"
	password := "4321"
	salt := "tokopedia-workshop"
	passwordPlain := []byte(password + salt)
	sha256 := sha256.Sum256(passwordPlain)
	hashedData := fmt.Sprintf("%x", sha256)

	//send data to server
	client := &http.Client{}
	method := "GET"
	url := "http://localhost:5000/profile?email=" + userEmail
	req, err := http.NewRequest(method, url, nil)
	req.Header.Add("sha", string(hashedData))
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var bodyPayload map[string]string
	json.Unmarshal(body, &bodyPayload)

	fPriv, err := ioutil.ReadFile("private.b")
	checkError(err)
	decoded, err := base64.StdEncoding.DecodeString(bodyPayload["Body"])
	checkError(err)
	decrypted := Decrypt(decoded, fPriv)
	fmt.Println("decrypted msg :", decrypted)
	return
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
