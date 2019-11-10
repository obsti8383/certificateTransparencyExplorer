// main.go
// Copyright 2018 Florian Probst.
// Aufruf mit mehreren Domains aus einer Textdatei via Powershell:
// (Get-Content .\domains.txt) |  % { invoke-expression  ".\CertificateTransparencyExplorer.exe $_" } >>all.csv

package main

import (
	"crypto/x509"
	//"encoding/json"
	"flag"
	"fmt"
	"log"
	"sort"
)

func main() {
	flag.Parse()

	//crt.sh
	ctentriesCRTSH, err := GetCTEntriesCRTSH(flag.Args()[0], false)
	if err != nil {
		log.Fatal("Error for " + flag.Args()[0] + ": " + err.Error())
	}
	log.Println(ctentriesCRTSH)

	//entrust
	ctentries, err := GetCTEntries(flag.Args()[0], false)
	if err != nil {
		log.Fatal("Error for " + flag.Args()[0] + ": " + err.Error())
	}

	sort.Sort(Certificates(ctentries))

	//printHeader()
	nrOfPreCerts := 0
	for _, entry := range ctentries {
		cert, _ := x509.ParseCertificate(entry.Cert)
		//b, _ := json.MarshalIndent(cert, "", "    ")
		isPreCertificate := false

		for _, unhandled := range cert.UnhandledCriticalExtensions {
			//log.Println(unhandled)

			if unhandled.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}) {
				//log.Printf("Precert found: %s", cert.SerialNumber)
				isPreCertificate = true
				nrOfPreCerts++
			}
			//  1.3.6.1.4.1.11129.2.4.3
		}
		//if !isPreCertificate {
		printCert(cert, isPreCertificate)
		//}
	}
	log.Println("#log entries:", len(ctentries))
	log.Println("#precerts:", nrOfPreCerts)

}

func printCert(cert *x509.Certificate, isPreCertificate bool) {
	fmt.Printf("%s;%t;%s;%s;\"%s\";%s;%s\n", cert.SerialNumber, isPreCertificate, cert.Issuer.CommonName, cert.Subject.CommonName, cert.DNSNames, cert.NotBefore.String(), cert.NotAfter.String())
}

func printHeader() {
	fmt.Printf("Serial Number;Precertificate;Issuer Common Name;Subject Common Name;DNS Names;Valid from;Valid till\n")
}

type Certificates []CTEntry

func (a Certificates) Len() int           { return len(a) }
func (a Certificates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Certificates) Less(i, j int) bool { return a[i].ValidFrom < a[j].ValidFrom }
