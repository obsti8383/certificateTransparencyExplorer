package main

import (
	"crypto/x509"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
)

// fetches CA certificates and CRLs from CDP and AIA fields
// alreadyFetched is used for recursive calls within this method. Just pass
// nil if you call it.
func fetchCAcertificatesAndCRLs(certificates []x509.Certificate, alreadyFetched map[string]bool) {
	if alreadyFetched == nil {
		alreadyFetched = make(map[string]bool)
	}

	// create directory for writing CA certs and CRLs to
	_ = os.Mkdir("cacerts", 0755)
	_ = os.Mkdir("crls", 0755)

	for _, cert := range certificates {
		cdps := cert.CRLDistributionPoints

		for _, cdp := range cdps {
			if strings.HasPrefix(cdp, "ldap://") {
				// ignoring LDAP CDPs
				continue
			}
			if alreadyFetched[cdp] == true {
				// do not fetch same CDP twice
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

			// write to file
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

			// write ca certificates to file
			_ = ioutil.WriteFile("cacerts/"+fetchedCert.Issuer.CommonName+"_"+fetchedCert.Subject.CommonName+".cer", body, 0644)

			if fetchedCert.Issuer.CommonName != fetchedCert.Subject.CommonName {
				// root ca not yet reached, go on fetching iteratively ...
				fetchCAcertificatesAndCRLs([]x509.Certificate{*fetchedCert}, alreadyFetched)
			}
		}
	}
}
