// Copyright 2017 Jeff Foley. (Thx to Jeff Foley, taken partly from https://github.com/caffix/amass/blob/master/amass/sources/entrust.go)
// Copyright 2018-2019 Florian Probst.

package main

import (
	"crypto/x509"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/url"
	"strconv"
)

const (
	USER_AGENT  = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
	ACCEPT      = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	ACCEPT_LANG = "en-US,en;q=0.8"
)

type San struct {
	Type          int    `json:"type"`
	ValueReversed string `json:"valueReversed"`
}

type CTEntry struct {
	//LogEntries []string `json:"logEntries"`
	Cert       []byte `json:"cert"`
	Thumbprint string `json:"thumbprint"`
	IssuerDN   string `json:"issuerDN"`
	SN         string `json:"sn"`
	SubjectDN  string `json:"subjectDN"`
	SignAlg    string `json:"signAlg"`
	San        []San  `json:"san"`
	ValidFrom  string `json:"validFrom"`
	ValidTo    string `json:"validTo"`
}

func GetCTEntries(domain string, includeExpired bool) (certificates []x509.Certificate, err error) {
	url := createGetUrl(domain, includeExpired)
	//log.Println("url:", url)
	jsonByteArray, err := getJSONfromWebservice(url, nil)
	if err != nil {
		return nil, err
	}

	//log.Println("jsonByteArray =", string(jsonByteArray))
	_ = ioutil.WriteFile("entrust_response.json", jsonByteArray, 0644)

	var ctentries []CTEntry
	err = json.Unmarshal(jsonByteArray, &ctentries)

	for _, entry := range ctentries {
		cert, err := x509.ParseCertificate(entry.Cert)
		if err != nil {
			log.Println(err.Error())
			return nil, err
		}
		certificates = append(certificates, *cert)
	}

	return certificates, err
}

func createGetUrl(domain string, includeExpired bool) string {
	u, _ := url.Parse("https://ctsearch.entrust.com/api/v1/certificates")

	u.RawQuery = url.Values{
		"fields":         {"issuerDN,subjectDN,san,sn,cert,validFrom,validTo"},
		"domain":         {domain},
		"includeExpired": {strconv.FormatBool(includeExpired)},
		"exactMatch":     {"false"},
		"limit":          {"5000"},
	}.Encode()
	return u.String()
}
