package main

import (
	"context"
	"crypto/x509"
	"errors"
	"log"
	"time"

	"github.com/unidoc/unipdf/v3/model"
	pdf "github.com/unidoc/unipdf/v3/model"
	globalsign "github.com/wja-id/globalsign-sdk"
	"github.com/wja-id/globalsign-sdk/integration"
)

type globalsignDssSigner struct {
	apiBase      string
	apiKey       string
	apiSecret    string
	certFilepath string
	keyFilepath  string

	manager *globalsign.Manager
}

// Load .
func (s *globalsignDssSigner) Load() error {
	// initiate globalsign sdk manager
	m, err := globalsign.NewManager(&globalsign.ManagerOption{
		APIKey:             s.apiKey,
		APISecret:          s.apiSecret,
		BaseURL:            s.apiBase,
		PrivateKeyPath:     s.keyFilepath,
		TLSCertificatePath: s.certFilepath,
	})
	if err != nil {
		return err
	}

	s.manager = m

	return nil
}

// Sign .
func (s *globalsignDssSigner) Sign(ctx context.Context, rd *model.PdfReader, option *SignOption) (*pdf.PdfAppender, error) {
	// ensure pdf is decrypted
	isEncrypted, err := rd.IsEncrypted()
	if err != nil {
		return nil, err
	}

	if isEncrypted {
		log.Println("pdf is encrypted")
		auth, err := rd.Decrypt([]byte(option.Password))
		if err != nil {
			return nil, err
		}
		if !auth {
			return nil, errors.New("cannot open encrypted document, please specify password in option")
		}
	}

	isEncrypted, err = rd.IsEncrypted()
	if err != nil {
		return nil, err
	}

	log.Println("pdf is encrypted?", isEncrypted)

	ap, err := model.NewPdfAppender(rd)
	if err != nil {
		return nil, err
	}

	signerIdentity := map[string]interface{}{
		"common_name": option.Fullname,
	}

	// Create signature handler.
	handler, err := integration.NewGlobalSignDSS(context.Background(), s.manager, option.SignedBy, signerIdentity)
	if err != nil {
		return nil, err
	}

	field, err := createSignatureField(option, handler)
	if err != nil {
		return nil, err
	}

	// get cert chain
	var certChain []*x509.Certificate
	if getter, ok := handler.(integration.CertificateChainGetter); ok {
		certChain = getter.GetCertificateChain()
	}

	// only sign first page
	if err = ap.Sign(1, field); err != nil {
		return nil, err
	}

	// add tlv
	ltv, err := model.NewLTV(ap)
	if err != nil {
		return nil, err
	}
	ltv.CertClient.HTTPClient.Timeout = 30 * time.Second
	ltv.OCSPClient.HTTPClient.Timeout = 30 * time.Second
	ltv.CRLClient.HTTPClient.Timeout = 1 * time.Microsecond // attempt to exclude crl

	err = ltv.EnableChain(certChain)
	if err != nil {
		return nil, err
	}

	return ap, nil
}

// NewGlobalSignDssSigner create and return instance signature
// generator backed by global sign
func NewGlobalSignDssSigner(param map[string]interface{}) Signer {
	mReader := NewMapReader(param)
	apiURL := mReader.String("provider.globalsign.api_url", "")
	apiKey := mReader.String("provider.globalsign.api_key", "")
	apiSecret := mReader.String("provider.globalsign.api_secret", "")
	apiCertFile := mReader.String("provider.globalsign.certificate", "")
	keyFile := mReader.String("provider.globalsign.private_key", "")

	return &globalsignDssSigner{
		apiBase:      apiURL,
		apiKey:       apiKey,
		apiSecret:    apiSecret,
		certFilepath: apiCertFile,
		keyFilepath:  keyFile,
	}
}

func init() {
	signerFactories["globalsign"] = NewGlobalSignDssSigner
}
