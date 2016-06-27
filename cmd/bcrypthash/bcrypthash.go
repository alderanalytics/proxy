package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/bcrypt"
)

var (
	cost = flag.Int("cost", bcrypt.DefaultCost, "set the bcrypt cost")
)

func die(err error) {
	fmt.Fprintf(os.Stderr, "%s\n", err)
	os.Exit(-1)
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <password>\n\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
	}

	flag.Parse()
	pass := flag.Arg(0)
	if pass == "" {
		flag.Usage()
		os.Exit(-1)
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(pass), *cost)
	if err != nil {
		die(err)
	}

	outPass, err := json.Marshal(bytes)
	if err != nil {
		die(err)
	}

	fmt.Println(string(outPass))
}
