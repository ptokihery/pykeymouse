//go:build !linux

package main

import "fmt"

func main() {
	fmt.Println("pykeymouse-server is only supported on Linux")
}
