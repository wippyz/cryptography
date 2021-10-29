package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
)

func main() {

	data := []byte("hello")
	secret := "my"
	Sha256(data)
	HMACSha256(data, secret)
	Sha384(data)
	Md5(data)
}

func Sha256(data []byte) {
	hash := sha256.Sum256(data)
	fmt.Printf("SHA256 hash result : %x \n", hash[:])
}

func HMACSha256(data []byte, secret string) {
	h := hmac.New(sha256.New, []byte(secret))

	// Write Data to it
	h.Write([]byte(data))

	// Get result and encode as hexadecimal string
	sha := hex.EncodeToString(h.Sum(nil))

	fmt.Println("HMAC-SHA256 hash result: " + sha)

}

func Sha384(data []byte) {
	hash := sha512.Sum384(data)
	fmt.Printf("SHA384 hash result : %x \n", hash[:])
}

func Md5(data []byte) {
	md5 := md5.Sum(data)
	result := fmt.Sprintf("Md5 hash result :%x \n", md5)
	fmt.Println(result)
}
