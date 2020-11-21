package main

import (
	"crypto/x509"
)

// type to allow to sort files based on validity date (NotBefore)
type Certificates []x509.Certificate

func (a Certificates) Len() int           { return len(a) }
func (a Certificates) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Certificates) Less(i, j int) bool { return a[i].NotBefore.Before(a[j].NotBefore) }
