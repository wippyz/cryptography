package main

import (
	"crypto/md5"
	"fmt"
)

func main() {
	data := []byte("tokopedia")
	md5 := md5.Sum(data)
	result := fmt.Sprintf("%x", md5)
	fmt.Println(result)
}
