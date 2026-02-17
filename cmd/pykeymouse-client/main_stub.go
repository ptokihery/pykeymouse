//go:build !windows

package main

import "fmt"

func main() {
	fmt.Println("pykeymouse-client is only supported on Windows")
}
