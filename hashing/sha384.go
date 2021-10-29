package main

import (
	"crypto/sha512"
	"fmt"
)

func main() {
	data := "tokopedia"
	sha384 := sha512.Sum384([]byte(data))
	fmt.Printf("sha384 hash result : %x \n", sha384)
}
