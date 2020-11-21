// Copyright 2019-2020 Florian Probst.

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strconv"
)

// Example crt.sh response dataset:
// {
//     "issuer_ca_id": 62124,
//     "issuer_name": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Thawte TLS RSA CA G1",
//     "name_value": "blablub.example.de",
//     "min_cert_id": 2086227961,
//     "min_entry_timestamp": "2019-11-08T10:27:16.191",
//     "not_before": "2019-11-08T00:00:00",
//     "not_after": "2021-12-07T12:00:00"
// }

// CTEntryCrtSh represent a certificate in the crt.sh response
type CTEntryCrtSh struct {
	IssuerDN    string `json:"issuer_name"`
	SubjectName string `json:"name_value"`
	ValidFrom   string `json:"not_before"`
	ValidTo     string `json:"not_after"`
	CrtshID     int    `json:"id"`
	IssuerCaID  int    `json:"issuer_ca_id"`
}

// GetCTEntriesCrtSh collects
func GetCTEntriesCrtSh(domain string, includeExpired bool) (certificates []x509.Certificate, err error) {
	var url string
	if includeExpired {
		url = "https://crt.sh/?q=%." + domain + "&output=json"
	} else {
		url = "https://crt.sh/?q=%." + domain + "&output=json&exclude=expired"
	}
	log.Println("Requesting crt.sh:", url)
	jsonByteArray, err := getJSONfromWebservice(url, nil)
	if err != nil {
		return nil, err
	}

	// write to file so one can have a look at the raw output from crt.sh
	_ = ioutil.WriteFile("crtsh_response.json", jsonByteArray, 0644)

	if string(jsonByteArray) == "[]" {
		return nil, errors.New("Empty answer - no certificates found")
	}

	var ctentries []CTEntryCrtSh
	err = json.Unmarshal(jsonByteArray, &ctentries)
	if err != nil {
		return nil, err
	}

	// create directory to write certs to
	_ = os.Mkdir("certs", 0755)

	// get complete certificate (as PEM) via: https://crt.sh/?d=2086227961 (min_cert_id)
	for _, certsh := range ctentries {
		url := "https://crt.sh/?d=" + strconv.Itoa(certsh.CrtshID)
		log.Println("downloading raw cert:", url)
		rawCert, err := getJSONfromWebservice(url, nil)
		if err != nil {
			return nil, err
		}

		derCert, _ := pem.Decode(rawCert)
		cert, err := x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}

		certificates = append(certificates, *cert)

		// save raw cert
		_ = ioutil.WriteFile("certs/"+cert.Issuer.CommonName+"_"+cert.Subject.CommonName+"_"+cert.SerialNumber.String()+".cer", rawCert, 0644)
	}

	return certificates, err
}
