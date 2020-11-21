package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

func getJSONfromWebservice(url string, hvals map[string]string) ([]byte, error) {
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

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return in, nil
}
