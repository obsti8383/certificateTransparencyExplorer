// Copyright 2017 Jeff Foley. (Thx to Jeff Foley, taken partly from https://github.com/caffix/amass/blob/master/amass/sources/entrust.go)
// Copyright 2018 Florian Probst.

package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
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

func GetCTEntries(domain string, includeExpired bool) (ctentries []CTEntry, err error) {
	url := createGetUrl(domain, includeExpired)
	//log.Println("url:", url)
	jsonByteArray, err := getJSONfromEntrust(url, nil)
	if err != nil {
		return ctentries, err
	}
	//log.Println("jsonByteArray =", jsonByteArray)
	err = json.Unmarshal(jsonByteArray, &ctentries)
	return ctentries, err
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

func getJSONfromEntrust(url string, hvals map[string]string) ([]byte, error) {
	d := net.Dialer{}
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext:           d.DialContext,
			MaxIdleConns:          200,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 5 * time.Second,
		},
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	req.Header.Add("User-Agent", USER_AGENT)
	req.Header.Add("Accept", ACCEPT)
	req.Header.Add("Accept-Language", ACCEPT_LANG)
	if hvals != nil {
		for k, v := range hvals {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
		return nil, err
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New(resp.Status)
	}

	//log.Println("resp: ", resp)

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return in, nil
}
