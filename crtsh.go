// Copyright 2019 Florian Probst.

package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"log"
	"strconv"
)

// Example:
// {
//     "issuer_ca_id": 62124,
//     "issuer_name": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Thawte TLS RSA CA G1",
//     "name_value": "blablub.example.de",
//     "min_cert_id": 2086227961,
//     "min_entry_timestamp": "2019-11-08T10:27:16.191",
//     "not_before": "2019-11-08T00:00:00",
//     "not_after": "2021-12-07T12:00:00"
// }
type CTEntryCRTSH struct {
	IssuerDN     string `json:"issuer_name"`
	SubjectName  string `json:"name_value"`
	ValidFrom    string `json:"not_before"`
	ValidTo      string `json:"not_after"`
	CRTSH_ID     int    `json:"id"`
	ISSUER_CA_ID int    `json:"issuer_ca_id"`
}

func GetCTEntriesCRTSH(domain string, includeExpired bool) (certificates []x509.Certificate, err error) {
	var url string
	if includeExpired {
		url = "https://crt.sh/?q=%." + domain + "&output=json"
	} else {
		url = "https://crt.sh/?q=%." + domain + "&output=json&exclude=expired"
	}
	log.Println("url:", url)
	jsonByteArray, err := getJSONfromWebservice(url, nil)
	if err != nil {
		return nil, err
	}

	_ = ioutil.WriteFile("crtsh_response.json", jsonByteArray, 0644)

	if string(jsonByteArray) == "[]" {
		return nil, errors.New("Empty answer - no certificates found")
	}

	var ctentries []CTEntryCRTSH
	err = json.Unmarshal(jsonByteArray, &ctentries)
	if err != nil {
		return nil, err
	}

	// get complete certificate (as PEM) via: https://crt.sh/?d=2086227961 (min_cert_id)
	for _, certsh := range ctentries {
		//log.Println("Getting certificate for: " + certsh.SubjectName + " EndDate: " + certsh.ValidTo)
		url := "https://crt.sh/?d=" + strconv.Itoa(certsh.CRTSH_ID)
		log.Println("url:", url)
		rawCert, err := getJSONfromWebservice(url, nil)
		if err != nil {
			return nil, err
		}
		//log.Println(string(rawCert))

		derCert, _ := pem.Decode(rawCert)
		cert, err := x509.ParseCertificate(derCert.Bytes)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}

		certificates = append(certificates, *cert)

		// raw cert wegspeichern
		_ = ioutil.WriteFile("certs/"+cert.Issuer.CommonName+"_"+cert.Subject.CommonName+"_"+cert.SerialNumber.String()+".cer", rawCert, 0644)
	}

	return certificates, err
}
