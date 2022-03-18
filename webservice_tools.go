package main

import (
	"errors"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"
)

const (
	userAgent  = "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36"
	accept     = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	acceptLang = "en-US,en;q=0.8"
)

// getJSONfromWebservice calls a webservices using URL url and header values hvals
// does NOT support paging, only collects first response page
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
		log.Println(err)
		return nil, err
	}

	req.Header.Add("User-Agent", userAgent)
	req.Header.Add("Accept", accept)
	req.Header.Add("Accept-Language", acceptLang)
	if hvals != nil {
		for k, v := range hvals {
			req.Header.Add(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return nil, err
	} else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, errors.New(resp.Status)
	}

	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Println(err)
		return nil, err
	}

	return in, nil
}
