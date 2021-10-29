package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	message := "hello"

	privKeyStr, err := ioutil.ReadFile("private_unencrypted.pem")

	if err != nil {
		log.Fatal(err)
	}

	privKey, err := ParseRsaPrivateKeyFromPemStr(string(privKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	//deterministic
	pkcs := SignPKCS(privKey, message)
	fmt.Println("signature PKCS:", pkcs)

	//non-deterministic
	pss := SignPSS(privKey, message)
	fmt.Println("Signature PSS :", pss)

	pubKeyStr, err := ioutil.ReadFile("public.pem")

	if err != nil {
		log.Fatal(err)
	}

	pubKey, err := ParseRsaPublicKeyFromPemStr(string(pubKeyStr))
	if err != nil {
		log.Fatal(err)
	}

	isVerified := VerifyPKCS(pubKey, message, pkcs)
	fmt.Println("isVerified PKCS: ", isVerified)

	isVerified = VerifyPSS(pubKey, message, pss)
	fmt.Println("isVerified PSS: ", isVerified)
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

func SignPKCS(privKey *rsa.PrivateKey, msg string) string {
	rng := rand.Reader
	message := []byte(msg)
	hashed := sha256.Sum256(message)

	signature, err := rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error from signing: %s\n", err)
		return ""
	}

	sEnc := base64.StdEncoding.EncodeToString(signature)
	return sEnc
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

func VerifyPKCS(pubKey *rsa.PublicKey, msg string, base64Signature string) bool {
	message := []byte(msg)
	bSignature, err := base64.StdEncoding.DecodeString(base64Signature)

	if err != nil {
		fmt.Println("Failed to decode signature")
		return false
	}
	hashed := sha256.Sum256(message)

	errVer := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], bSignature)
	if errVer != nil {
		fmt.Fprintf(os.Stderr, "Error from verification %s\n", errVer)
		return false
	}

	return true
}
