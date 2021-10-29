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
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "ping",
		})
	})
	r.GET("/profile", GetProfile)
	r.Run(":5000")
}

func GetProfile(c *gin.Context) {
	userData := make(map[string]string)
	userData["wippy@tokopedia.com"] = "58f01f107545b6df4465f2b4752d87c9afb3a30d08fe8be883597577d75598c7"
	userData["fahrur@tokopedia.com"] = "ede0fccd79cf0072447ed4ff50eb63105429c62965dbb5a4ca8557caf1c75a2b"
	email := c.Query("email")
	fmt.Println("email", email)
	sha := c.GetHeader("sha")
	fmt.Println("sha", sha)
	if userData[email] != sha {
		c.JSON(http.StatusForbidden, gin.H{
			"Body": "failed",
		})
		return
	}

	fPub, err := ioutil.ReadFile("public.b")
	checkError(err)

	nameArr := strings.Split(email, "@")
	payload := "hello " + nameArr[0]

	encrypted := base64.StdEncoding.EncodeToString(Encrypt([]byte(payload), fPub))
	encrypted = strings.TrimSpace(encrypted)
	c.JSON(http.StatusOK, gin.H{
		"Body": encrypted,
	})
	return
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
