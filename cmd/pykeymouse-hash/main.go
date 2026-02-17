package main

import (
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	var password string
	var cost int
	flag.StringVar(&password, "password", "", "password (optional; will prompt if empty)")
	flag.IntVar(&cost, "cost", 12, "bcrypt cost")
	flag.Parse()

	var passBytes []byte
	if password != "" {
		passBytes = []byte(password)
	} else {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read password failed:", err)
			os.Exit(1)
		}
		passBytes = b
	}

	hash, err := bcrypt.GenerateFromPassword(passBytes, cost)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bcrypt failed:", err)
		os.Exit(1)
	}
	fmt.Println(string(hash))
}
