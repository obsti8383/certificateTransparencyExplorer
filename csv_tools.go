package main

import (
	"crypto/x509"
	"fmt"
	"log"
	"os"
)

// writeCSV writes a x509 certificate array to a file
// verifies if a certificate is a "Precertificate" and sets attribute in CSV
// accordingly
func writeCSV(certificates []x509.Certificate) {
	f, err := os.Create("certificates.csv")
	if err != nil {
		log.Println(err)
		f.Close()
		return
	}
	defer f.Close()

	writeHeader(f)
	nrOfPreCerts := 0
	for _, cert := range certificates {
		isPreCertificate := false

		for _, unhandled := range cert.UnhandledCriticalExtensions {
			//  1.3.6.1.4.1.11129.2.4.3
			if unhandled.Equal([]int{1, 3, 6, 1, 4, 1, 11129, 2, 4, 3}) {
				isPreCertificate = true
				nrOfPreCerts++
			}
		}
		writeCert(f, cert, isPreCertificate)
	}

	err = f.Close()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Number of precerts written to CSV:", nrOfPreCerts)
	log.Println("CSV file certificates.csv written successfully")
}

func writeCert(f *os.File, cert x509.Certificate, isPreCertificate bool) {
	fmt.Fprintf(f, "%s;%t;%s;%s;\"%s\";%s;%s\n", cert.SerialNumber, isPreCertificate, cert.Issuer.CommonName, cert.Subject.CommonName, cert.DNSNames, cert.NotBefore.String(), cert.NotAfter.String())
}

func writeHeader(f *os.File) {
	fmt.Fprintf(f, "Serial Number;Precertificate;Issuer Common Name;Subject Common Name;DNS Names;Valid from;Valid till\n")
}
