// main.go
// Copyright 2018 Florian Probst.

package main

import (
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
)

func main() {
	flag.Parse()
	ctentries, _ := GetCTEntries(flag.Args()[0], false)
	for _, entry := range ctentries {
		cert, _ := x509.ParseCertificate(entry.Cert)
		b, _ := json.MarshalIndent(cert, "", "    ")
		fmt.Println(string(b))
	}
}
