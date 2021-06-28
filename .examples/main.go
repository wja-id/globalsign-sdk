package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/unidoc/unipdf/v3/common"
	"github.com/unidoc/unipdf/v3/common/license"
)

var (
	inputFile  string
	outputFile string
	email      string
	fullname   string
	reason     string

	certPath string
	keyPath  string
)

// unipdf license
var (
	licenseKey  = ""
	companyName = ""
)

// globalsign DSS credential
var (
	apiKey     = ""
	apiSecret  = ""
	apiBaseURL = "https://emea.api.dss.globalsign.com:8443/v2"
)

// loadLicense register unidoc license
func loadLicense() error {
	return license.SetLicenseKey(licenseKey, companyName)
}

func main() {
	common.SetLogger(common.NewConsoleLogger(common.LogLevelDebug))

	// ensure unipdf license is set
	if err := loadLicense(); err != nil {
		fmt.Println("license error: ", err)
		os.Exit(1)
	}

	flag.StringVar(&inputFile, "input-file", "", "file to be signed (required)")
	flag.StringVar(&outputFile, "output-file", "", "output result (required)")
	flag.StringVar(&email, "email", "", "email for signer identity (required)")
	flag.StringVar(&apiKey, "api-key", "", "API key (required)")
	flag.StringVar(&apiSecret, "api-secret", "", "API secret (required)")
	flag.StringVar(&certPath, "cert-file", "tls.cer", "certificate file for API (required)")
	flag.StringVar(&keyPath, "key-file", "key.pem", "key file for API (required)")
	flag.StringVar(&fullname, "name", "your n@me", "signer name")
	flag.StringVar(&reason, "reason", "enter your re@son", "signing reason")

	flag.Parse()

	if inputFile == "" || outputFile == "" || email == "" || apiKey == "" || apiSecret == "" || certPath == "" || keyPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	option := &SignOption{
		SignedBy: "tems.sg",
		Fullname: "Tunneling and Excavation Monitoring System",
		Reason:   "testing globalsign DSS",
		Annotate: true,
	}

	sigGen := NewGlobalSignDssSigner(map[string]interface{}{
		"provider.globalsign.api_url":     apiBaseURL,
		"provider.globalsign.api_key":     apiKey,
		"provider.globalsign.api_secret":  apiSecret,
		"provider.globalsign.certificate": certPath,
		"provider.globalsign.private_key": keyPath,
	})

	if err := SignFile(context.Background(), inputFile, outputFile, option, sigGen); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println("File signed successfully")
}
