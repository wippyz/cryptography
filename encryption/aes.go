package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
)

func main() {
	log.SetFlags(log.Lshortfile)
	encrypted := encrypt("thisisthemessage", "12345678901234511234567890123key")
	fmt.Printf("encrypted %s\n", encrypted)

	decrypted := decrypt("kEN5RlBgi7cjA/CP69NohgByVQ3WCRnj+L18ahn4jEBVvbS7tTk1a2hSdbU=", "12345678901234511234567890123key")
	fmt.Printf("decrypted %s\n", decrypted)
}

func encrypt(text string, key string) string {

	plaintext := []byte(text)
	keybyte := []byte(key)

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	block, err := aes.NewCipher(keybyte)
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)
	log.Println(ciphertext)
	encoded := base64.StdEncoding.EncodeToString([]byte(ciphertext))
	return encoded
}

func decrypt(encrypted string, key string) string {

	decoded, err := base64.StdEncoding.DecodeString(encrypted)
	nonce := decoded[len(decoded)-12:]
	decoded = decoded[:len(decoded)-12]

	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err.Error())
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	plaintext, err := aesgcm.Open(nil, nonce, decoded, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("%s\n", plaintext)
	return string(plaintext)

}
