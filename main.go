// Certificate Transparency Explorer
// Copyright 2018-2020 Florian Probst

package main

import (
	"bufio"
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

func main() {
	flag.Parse()
	if len(flag.Args()) > 1 {
		log.Println("Usage: .\\certificateTransparencyExplorer <filename of file that contains a list of domains>")
		log.Println("Example: .\\certificateTransparencyExplorer domains.txt")
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
		// get certificates from crt.sh, do not include expired certificates
		certsCRTSH, err := GetCTEntriesCrtSh(domain, false)
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

	log.Println("Number of transparency log entries found:", len(allCerts))

	fetchCAcertificatesAndCRLs(allCerts, nil)
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
