# CertificateTransparencyExplorer
Gets list of certificates from certificate transparency logs (currently crt.sh, only non-expired certificates) for a specified list of domains and writes a CSV file (certificates.csv) that gives an overview of all the certificates found.

Examples usage:

<code>./CertificateTransparencyExplorer domains.txt</code>

where domains.txt contains a plain list of domains, e.g.:

<pre><code>heise.de
github.com</pre></code>


Additionally all certificates are fetched from crt.sh, including CA certificates and CRLs and saved in the directories certs, cacerts and crls.

Beneath that all subdomains found in issued certificates are collected an written to file `certificate_domains_found.txt`. This can e.g. be used for finding unknown subdomains in the information gathering phase of an penetration test. Hint: You might also find new domains in certificates. If you iteratively call CertificateTransparencyExplorer with those new domains you might even find more (sub)domains.

For those who like to look at the raw JSON response from crt.sh this is also written to a file (`crtsh_response.json`).
