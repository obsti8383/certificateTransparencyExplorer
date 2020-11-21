# CertificateTransparencyExplorer
Gets list of certificates from certificate transparency logs (currently crt.sh, only non-expired certificates) for a specified list of domains and writes a CSV file (certificates.csv) that gives an overview of all the certificates found.

Examples usage:

<code>./CertificateTransparencyExplorer domains.txt</code>

where domains.txt contains a plain list of top level domains, e.g.:

<pre><code>heise.de
github.com</pre></code>


Additionally all certificates are fetched from crt.sh, including CA certificates and CRLs and saved in the directories certs, cacerts and crls.
