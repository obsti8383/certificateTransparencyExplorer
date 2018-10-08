// main.go
// Copyright 2018 Florian Probst.
// Aufruf mit mehreren Domains aus einer Textdatei via Powershell:  (Get-Content .\domains.txt) |  % { invoke-expression  ".\CertificateTransparencyExplorer.exe $_" } >>all.csv

package main

import (
	"crypto/x509"
	//"encoding/json"
	"flag"
	"fmt"
)

func main() {
	flag.Parse()
	ctentries, _ := GetCTEntries(flag.Args()[0], false)
	//printHeader()
	for _, entry := range ctentries {
		cert, _ := x509.ParseCertificate(entry.Cert)
		//b, _ := json.MarshalIndent(cert, "", "    ")
		printCert(cert)
	}
}

func printCert(cert *x509.Certificate) {
	fmt.Printf("%s;%s;%s;\"%s\";%s;%s\n", cert.SerialNumber, cert.Issuer.CommonName, cert.Subject.CommonName, cert.DNSNames, cert.NotBefore.String(), cert.NotAfter.String())
}

func printHeader() {
	fmt.Printf("Serial Number;Issuer Common Name;Subject Common Name;DNS Names;Valid from;Valid till\n")
}
