// main.go
// Copyright 2018-2019 Florian Probst.
// Aufruf mit mehreren Domains aus einer Textdatei via Powershell:
// (Get-Content .\domains.txt) |  % { invoke-expression  ".\CertificateTransparencyExplorer.exe $_" } >>all.csv

package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"sort"
)

func main() {
	flag.Parse()
	if len(flag.Args()) < 1 {
		fmt.Println("Usage: .\\CertificateTransparencyExplorer <dnsname>")
		fmt.Println("Example: .\\CertificateTransparencyExplorer mydomain.com")
		return
	}

	//crt.sh
	certsCRTSH, err := GetCTEntriesCRTSH(flag.Args()[0], false)
	if err != nil {
		log.Fatal("Error for " + flag.Args()[0] + ": " + err.Error())
	}

	//entrust
	certsEntrust, err := GetCTEntries(flag.Args()[0], false)
	if err != nil {
		log.Fatal("Error for " + flag.Args()[0] + ": " + err.Error())
	}

	allCerts := append(certsCRTSH, certsEntrust...)

	sort.Sort(Certificates(allCerts))

	//printHeader()
	nrOfPreCerts := 0
	for _, cert := range allCerts {
		isPreCertificate := false

		for _, unhandled := range cert.UnhandledCriticalExtensions {
			//  1.3.6.1.4.1.11129.2.4.3
			if unhandled.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}) {
				isPreCertificate = true
				nrOfPreCerts++
			}
		}
		printCert(cert, isPreCertificate)
	}

	log.Println("#entrust entries:", len(certsEntrust))
	log.Println("#crtsh entries:", len(certsCRTSH))

	log.Println("#log entries:", len(allCerts))
	log.Println("#precerts:", nrOfPreCerts)
}

func printCert(cert x509.Certificate, isPreCertificate bool) {
	fmt.Printf("%s;%t;%s;%s;\"%s\";%s;%s\n", cert.SerialNumber, isPreCertificate, cert.Issuer.CommonName, cert.Subject.CommonName, cert.DNSNames, cert.NotBefore.String(), cert.NotAfter.String())
}

func printHeader() {
	fmt.Printf("Serial Number;Precertificate;Issuer Common Name;Subject Common Name;DNS Names;Valid from;Valid till\n")
}

type Certificates []x509.Certificate

func (a Certificates) Len() int           { return len(a) }
func (a Certificates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Certificates) Less(i, j int) bool { return a[i].NotBefore.Before(a[j].NotBefore) }
