package main

import (
	"bytes"
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
	"strings"
)

func main() {

	//create payload
	message := make(map[string]string)
	message["email"] = "wippy@tokopedia.com"
	message["amount"] = "10000"
	messageStr, err := json.Marshal(message)

	//read private key
	privKeyStr, err := ioutil.ReadFile("a-private.key")
	if err != nil {
		log.Fatal(err)
	}

	privKey, err := ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	//create signature
	signaturePSS := SignPSS(privKey, string(messageStr))

	//encrypt message
	fPub, err := ioutil.ReadFile("b-public.key")
	checkError(err)
	encrypted := base64.StdEncoding.EncodeToString(Encrypt(messageStr, fPub))
	encrypted = strings.TrimSpace(encrypted)

	//send data to server
	client := &http.Client{}
	method := "POST"
	url := "http://localhost:5000/payment"

	payload := make(map[string]string)

	payload["body"] = encrypted

	payloadByte, err := json.Marshal(payload)
	if err != nil {
		log.Println(err)
		return
	}
	signaturePSS += "waojoawjaw"
	payloadBuffer := bytes.NewReader(payloadByte)
	req, err := http.NewRequest(method, url, payloadBuffer)
	req.Header.Add("signature", signaturePSS)
	res, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return
	}
	defer res.Body.Close()

	//read response
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		log.Println(err)
		return
	}
	var bodyPayload map[string]string
	json.Unmarshal(body, &bodyPayload)
	fmt.Println(bodyPayload)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func SignPSS(privKey *rsa.PrivateKey, msg string) string {
	rng := rand.Reader
	message := []byte(msg)
	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPSS(rng, privKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return ""
	}

	sEnc := base64.StdEncoding.EncodeToString(signature)
	return sEnc
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
	fmt.Println("encrypting: ", string(msg))
	return ciphertext
}

func checkError(err error) {
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
		os.Exit(1)
	}
}
