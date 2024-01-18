package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
)

// FetchCertificate fetches a certificate from a given URL
func FetchCertificate(url string) (*x509.Certificate, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// We will need both immediate and root CA from here. Will need to tweak this.
import (
	"strings"
)

func GetIssuerURLs(cert *x509.Certificate) ([]string, error) {
	var urls []string
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidAuthorityInfoAccess) {
			// Parse the extension to extract the URL
			value := string(ext.Value)
			lines := strings.Split(value, "\n")
			for _, line := range lines {
				if strings.Contains(line, "URL=") {
					url := strings.TrimPrefix(line, "URL=")
					urls = append(urls, url)
				}
			}
		}
	}
	return urls, nil
}


// Given a EK Cert this pull the URLs and using the URL fetch the certificate.
func main() {
	// Load the TPM endorsement certificate
	// This can be from a file, or directly from the TPM

	// Read the certificate from a file
	certPEMFile := "/path/to/cert.pem"
	certPEM, err := os.ReadFile(certPEMFile)
	if err != nil {
		fmt.Println("Failed to read certificate file:", err)
		return
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("Failed to decode PEM block containing the certificate")
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse certificate:", err)
		return
	}

	issuerURLs, err := GetIssuerURLs(cert)
	if err != nil {
		fmt.Println("Failed to extract issuer URLs:", err)
		return
	}

	for _, url := range issuerURLs {
		issuerCert, err := FetchCertificate(url)
		if err != nil {
			fmt.Println("Failed to fetch issuer certificate:", err)
			continue
		}
		fmt.Println("Fetched issuer certificate:", issuerCert.Subject)
	}
}

   // Will need to see PEM DER conversion in the script. 
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Println("Failed to decode PEM block containing the certificate")
		return
	}
    // Can EK cert be parsed as X05 ?  Assuming yes since EKCert are
	// x509. 
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		fmt.Println("Failed to parse certificate:", err)
		return
	}

	issuerURLs, err := r(cert)
	if err != nil {
		fmt.Println("Failed to extract issuer URLs:", err)
		return
	}

	for _, url := range issuerURLs {
		issuerCert, err := FetchCertificate(url)
		if err != nil {
			fmt.Println("Failed to fetch issuer certificate:", err)
			continue
		}
		fmt.Println("Fetched issuer certificate:", issuerCert.Subject)
	}
}
