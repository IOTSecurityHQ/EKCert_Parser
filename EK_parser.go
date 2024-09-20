package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
)

// Return codes for downloadCertificate function
const (
	RootReached = iota   //  this is like enum in C
	Success
	Error
)

// certificateChain stores the entire chain of certificates.
var certificateChain []string

// downloadCertificate downloads the issuing certificate from the Authority Info Access field in the given certificate data.
func downloadCertificate(certData []byte) (int, []byte, error) {
	// Parse the certificate
	block, _ := pem.Decode(certData)
	if block == nil {
		return Error, nil, fmt.Errorf("failed to decode certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Error, nil, fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Explicit root certificate check (self-signed)
	if cert.Subject.CommonName == cert.Issuer.CommonName {
		return RootReached, nil, nil // Root certificate reached
	}

	// Extract Authority Info Access field to get the URL of the issuing certificate
	match := regexp.MustCompile(`Authority Info Access: ([^\n]+)`).FindStringSubmatch(string(certData))
	if len(match) < 2 {
		return Error, nil, errors.New("Authority Info Access field not found in certificate")
	}
	url := match[1]

	// Download the issuing certificate from the URL
	response, err := http.Get(url)
	if err != nil {
		return Error, nil, fmt.Errorf("failed to download issuing certificate from URL: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return Error, nil, fmt.Errorf("failed to download issuing certificate, status code: %d", response.StatusCode)
	}

	// Read and return the issuing certificate content
	issuingCertData, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return Error, nil, fmt.Errorf("failed to read issuing certificate data: %v", err)
	}

	return Success, issuingCertData, nil
}

// downloadCertChain downloads the entire certificate chain starting from the given certificate file.
func downloadCertChain(certFilePath string) error {
	// Read the initial certificate from the file
	certData, err := ioutil.ReadFile(certFilePath)
	if err != nil {
		return fmt.Errorf("failed to read certificate file: %v", err)
	}

	// Start downloading the certificate chain
	for {
		// Add the current certificate to the chain
		certificateChain = append(certificateChain, string(certData))

		// Download the next certificate in the chain
		status, issuingCertData, err := downloadCertificate(certData)
		if err != nil {
			return fmt.Errorf("error in downloading certificate chain: %v", err)
		}

		// Handle return codes
		switch status {
		case RootReached:
			fmt.Println("Reached the root certificate.")
			return nil // Stop the process when reaching the root certificate
		case Success:
			// Update certData to the issuing certificate and continue
			certData = issuingCertData
		case Error:
			return fmt.Errorf("an error occurred in the certificate chain: %v", err)
		}
	}
}

func main() {
	// Replace with the actual initial certificate file path
	filePath := "/path/to/your/certificate.pem"

	// Attempt to download the certificate chain
	err := downloadCertChain(filePath)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Print the entire certificate chain
	for i, cert := range certificateChain {
		fmt.Printf("Certificate %d:\n%s\n", i+1, cert)
	}
}
