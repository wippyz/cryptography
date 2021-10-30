package main

import (
	"crypto/sha256"
	"fmt"
)

func main() {
	data := []byte("tokopedia")
	sha256 := sha256.Sum256(data)
	result := fmt.Sprintf("%x", sha256)
	fmt.Println(result)
}
