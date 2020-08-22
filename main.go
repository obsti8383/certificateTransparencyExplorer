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
		log.Println("Usage: .\\CertificateTransparencyExplorer <filename with list of domains>")
		log.Println("Example: .\\CertificateTransparencyExplorer domains.txt")
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

		// Entrust currently not working / out-of service
		// TODO: Instead implement: https://transparencyreport.google.com, API is exposed
		//  through https://transparencyreport.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch?include_subdomains=true&domain=google.com
		// certsEntrust, err := GetCTEntries(domain, false)
		// if err != nil {
		// 	log.Println("Entrust: Error for " + domain + ": " + err.Error())
		// }
		// if certsEntrust != nil {
		// 	allCerts = append(allCerts, certsEntrust...)
		// }
	}

	sort.Sort(Certificates(allCerts))

	writeCSV(allCerts)
	writeDNSList(allCerts)

	//log.Println("#entrust entries:", len(certsEntrust))
	//log.Println("#crtsh entries:", len(certsCRTSH))

	log.Println("#log entries:", len(allCerts))

	fetchCAcertificatesAndCRLs(allCerts, nil)
}

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
	log.Println("#precerts:", nrOfPreCerts)
	log.Println("certificates.csv written successfully")

}

func fetchCAcertificatesAndCRLs(certificates []x509.Certificate, alreadyFetched map[string]bool) {
	if alreadyFetched == nil {
		alreadyFetched = make(map[string]bool)
	}

	for _, cert := range certificates {
		cdps := cert.CRLDistributionPoints

		for _, cdp := range cdps {
			if strings.HasPrefix(cdp, "ldap://") {
				// ignoring LDAP CDPs
				continue
			}
			if alreadyFetched[cdp] == true {
				continue
			}

			log.Println("Fetching CRL: " + cdp)
			resp, err := http.Get(cdp)
			alreadyFetched[cdp] = true
			if err != nil {
				// handle error
				log.Println("Fetching CRL " + cdp + " resulted in error: " + err.Error())
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			_ = ioutil.WriteFile("crls/"+cert.Issuer.CommonName+".crl", body, 0644)
		}

		aias := cert.IssuingCertificateURL
		for _, aia := range aias {
			if strings.HasPrefix(aia, "ldap://") {
				// ignoring LDAP AIAs
				continue
			}
			if alreadyFetched[aia] == true {
				continue
			}

			log.Println("Fetching CA cert: " + aia)
			resp, err := http.Get(aia)
			alreadyFetched[aia] = true
			if err != nil {
				// handle error
				log.Println("Fetching CA cert " + aia + " resulted in error: " + err.Error())
				continue
			}
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			fetchedCert, err := x509.ParseCertificate(body)
			if err != nil {
				log.Println("Parsing CA cert " + aia + " resulted in error: " + err.Error())
				continue
			}
			_ = ioutil.WriteFile("certs/"+fetchedCert.Issuer.CommonName+"_"+fetchedCert.Subject.CommonName+".cer", body, 0644)

			if fetchedCert.Issuer.CommonName != fetchedCert.Subject.CommonName {
				// no root ca, go on fetching...
				fetchCAcertificatesAndCRLs([]x509.Certificate{*fetchedCert}, alreadyFetched)
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
		line := scanner.Text()
		if !strings.HasPrefix(line, "#") {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

func writeDNSList(certificates []x509.Certificate) {
	domainMap := make(map[string]bool)
	f, err := os.Create("certificate_domains_found.txt")
	if err != nil {
		log.Println(err)
		f.Close()
		return
	}
	defer f.Close()

	for _, cert := range certificates {
		if domainMap[cert.Subject.CommonName] != true {
			fmt.Fprintln(f, cert.Subject.CommonName)
			domainMap[cert.Subject.CommonName] = true
		}
		for _, dnsName := range cert.DNSNames {
			if domainMap[dnsName] != true {
				fmt.Fprintln(f, dnsName)
				domainMap[dnsName] = true
			}
		}
	}

	err = f.Close()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("certificate_domains_found.txt written successfully")
}

type Certificates []x509.Certificate

func (a Certificates) Len() int           { return len(a) }
func (a Certificates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Certificates) Less(i, j int) bool { return a[i].NotBefore.Before(a[j].NotBefore) }
