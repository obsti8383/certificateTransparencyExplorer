// Copyright 2019 Florian Probst.

package main

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

// Example:
// {
//     "issuer_ca_id": 62124,
//     "issuer_name": "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Thawte TLS RSA CA G1",
//     "name_value": "mebp.web.porsche.de",
//     "min_cert_id": 2086227961,
//     "min_entry_timestamp": "2019-11-08T10:27:16.191",
//     "not_before": "2019-11-08T00:00:00",
//     "not_after": "2021-12-07T12:00:00"
// }
type CTEntryCRTSH struct {
	IssuerDN    string `json:"issuer_name"`
	subjectName string `json:"name_value"`
	ValidFrom   string `json:"not_before"`
	ValidTo     string `json:"not_after"`
}

func GetCTEntriesCRTSH(domain string, includeExpired bool) (ctentries []CTEntryCRTSH, err error) {
	url := "https://crt.sh/?q=%." + domain + "&output=json"
	log.Println("url:", url)
	jsonByteArray, err := getJSONfromCRTSH(url, nil)
	if err != nil {
		return nil, err
	}

	//log.Println("jsonByteArray =", string(jsonByteArray))
	_ = ioutil.WriteFile("crtsh_response.json", jsonByteArray, 0644)

	err = json.Unmarshal(jsonByteArray, &ctentries)

	// TODO: get complete certificate (as PEM) via: https://crt.sh/?d=2086227961 (min_cert_id)
	return ctentries, err
}

func getJSONfromCRTSH(url string, hvals map[string]string) ([]byte, error) {
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
