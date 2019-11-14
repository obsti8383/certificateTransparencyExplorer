// main.go
// Copyright 2018-2019 Florian Probst.

package main

import (
	"bufio"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sort"
	"strings"
)

func main() {
	flag.Parse()
	if len(flag.Args()) > 1 {
		fmt.Println("Usage: .\\CertificateTransparencyExplorer <filename with list of domains>")
		fmt.Println("Example: .\\CertificateTransparencyExplorer domains.txt")
		return
	}

	var domainsFile string
	if len(flag.Args()) < 1 {
		domainsFile = "domains.txt"
	} else {
		domainsFile = flag.Args()[0]
	}

	domains, err := getDomainsFromFile(domainsFile)
	if err != nil {
		log.Fatalln("Error opening domains file: " + domainsFile)
	}

	allCerts := make([]x509.Certificate, 0)
	for _, domain := range domains {
		//crt.sh
		certsCRTSH, err := GetCTEntriesCRTSH(domain, false)
		if err != nil {
			log.Println("crt.sh: Error for " + domain + ": " + err.Error())
		}
		if certsCRTSH != nil {
			allCerts = append(allCerts, certsCRTSH...)
		}

		//entrust
		certsEntrust, err := GetCTEntries(domain, false)
		if err != nil {
			log.Println("Entrust: Error for " + domain + ": " + err.Error())
		}
		if certsEntrust != nil {
			allCerts = append(allCerts, certsEntrust...)
		}
	}

	sort.Sort(Certificates(allCerts))

	writeCSV(allCerts)

	//log.Println("#entrust entries:", len(certsEntrust))
	//log.Println("#crtsh entries:", len(certsCRTSH))

	log.Println("#log entries:", len(allCerts))

	fetchCAcertificatesAndCRLs(allCerts)
}

func writeCSV(certificates []x509.Certificate) {
	f, err := os.Create("certificates.csv")
	if err != nil {
		fmt.Println(err)
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
		fmt.Println(err)
		return
	}
	fmt.Println("certificates.csv written successfully")

	log.Println("#precerts:", nrOfPreCerts)
}

func fetchCAcertificatesAndCRLs(certificates []x509.Certificate) {
	// TODO: also fetch Root & Intermediate CAs one level above the EE certificate
	for _, cert := range certificates {
		cdps := cert.CRLDistributionPoints

		for _, cdp := range cdps {
			if strings.HasPrefix(cdp, "ldap://") {
				// ignoring LDAP CDPs
				continue
			}
			fmt.Println("Fetching CRL: " + cdp)
			resp, err := http.Get(cdp)
			if err != nil {
				// handle error
				fmt.Println("Fetching CRL " + cdp + " resulted in error: " + err.Error())
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			_ = ioutil.WriteFile(cert.Issuer.CommonName+".crl", body, 0644)
		}

		aias := cert.IssuingCertificateURL
		for _, aia := range aias {
			if strings.HasPrefix(aia, "ldap://") {
				// ignoring LDAP AIAs
				continue
			}
			fmt.Println("Fetching CA cert: " + aia)
			resp, err := http.Get(aia)
			if err != nil {
				// handle error
				fmt.Println("Fetching CA cert " + aia + " resulted in error: " + err.Error())
				continue
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			fetchedCert, err := x509.ParseCertificate(body)
			if err != nil {
				fmt.Println("Parsing CA cert " + aia + " resulted in error: " + err.Error())
				continue
			}
			_ = ioutil.WriteFile(fetchedCert.Issuer.CommonName+"_"+fetchedCert.Subject.CommonName+".cer", body, 0644)

			if fetchedCert.Issuer.CommonName != fetchedCert.Subject.CommonName {
				// no root ca, go on fetching...
				fetchCAcertificatesAndCRLs([]x509.Certificate{*fetchedCert})
			}
		}
	}
}

func writeCert(f *os.File, cert x509.Certificate, isPreCertificate bool) {
	fmt.Fprintf(f, "%s;%t;%s;%s;\"%s\";%s;%s\n", cert.SerialNumber, isPreCertificate, cert.Issuer.CommonName, cert.Subject.CommonName, cert.DNSNames, cert.NotBefore.String(), cert.NotAfter.String())
}

func writeHeader(f *os.File) {
	fmt.Fprintf(f, "Serial Number;Precertificate;Issuer Common Name;Subject Common Name;DNS Names;Valid from;Valid till\n")
}

func getDomainsFromFile(filename string) (domains []string, err error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domains = append(domains, scanner.Text())
	}
	return domains, scanner.Err()
}

type Certificates []x509.Certificate

func (a Certificates) Len() int           { return len(a) }
func (a Certificates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Certificates) Less(i, j int) bool { return a[i].NotBefore.Before(a[j].NotBefore) }
