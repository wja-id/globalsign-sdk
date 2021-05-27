package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/unidoc/unipdf/v3/core"
	"github.com/unidoc/unipdf/v3/model"
	globalsign "github.com/wja-id/globalsign-sdk"
	"github.com/wja-id/pkcs7"
)

const sigLen = 8192

// GlobalsignDSS is custom unidoc sighandler which leverage
// globalsign DSS service
type GlobalsignDSS struct {
	signer   string
	identity map[string]interface{}

	manager *globalsign.Manager

	// a caller context
	ctx context.Context
}

func (h *GlobalsignDSS) getCertificate(sig *model.PdfSignature) (*x509.Certificate, error) {

	var certData []byte
	switch certObj := sig.Cert.(type) {
	case *core.PdfObjectString:
		certData = certObj.Bytes()
	case *core.PdfObjectArray:
		if certObj.Len() == 0 {
			return nil, errors.New("no signature certificates found")
		}
		for _, obj := range certObj.Elements() {
			certStr, ok := core.GetString(obj)
			if !ok {
				return nil, fmt.Errorf("invalid certificate object type in signature certificate chain: %T", obj)
			}
			certData = append(certData, certStr.Bytes()...)
		}
	default:
		return nil, fmt.Errorf("invalid signature certificate object type: %T", certObj)
	}

	certs, err := x509.ParseCertificates(certData)
	if err != nil {
		return nil, err
	}

	return certs[0], nil
}

// IsApplicable .
func (h *GlobalsignDSS) IsApplicable(sig *model.PdfSignature) bool {
	if sig == nil || sig.Filter == nil || sig.SubFilter == nil {
		return false
	}
	return (*sig.Filter == "Adobe.PPKMS" || *sig.Filter == "Adobe.PPKLite") && *sig.SubFilter == "adbe.pkcs7.detached"
}

// Validate .
func (h *GlobalsignDSS) Validate(sig *model.PdfSignature, digest model.Hasher) (model.SignatureValidationResult, error) {

	return model.SignatureValidationResult{
		IsSigned:   true,
		IsVerified: true,
	}, nil
}

// InitSignature sets the PdfSignature parameters.
func (h *GlobalsignDSS) InitSignature(sig *model.PdfSignature) error {
	// request new identification based on signer
	identity, err := h.manager.GetIdentity(h.ctx, h.signer, &globalsign.IdentityRequest{
		SubjectDn: h.identity,
	})
	if err != nil {
		return err
	}

	// create certificate chain
	// from signing and ca cert
	var certChain []*x509.Certificate
	issuerCertData := []byte(identity.SigningCert)
	for len(issuerCertData) != 0 {
		var block *pem.Block
		block, issuerCertData = pem.Decode(issuerCertData)
		if block == nil {
			break
		}

		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		certChain = append(certChain, issuer)
	}

	caCertData := []byte(identity.CA)
	for len(caCertData) != 0 {
		var block *pem.Block
		block, caCertData = pem.Decode(caCertData)
		if block == nil {
			break
		}

		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}

		certChain = append(certChain, issuer)
	}

	// Create PDF array object which will contain the certificate chain data
	pdfCerts := core.MakeArray()
	for _, cert := range certChain {
		pdfCerts.Append(core.MakeString(string(cert.Raw)))
	}

	// append cert to signature
	sig.Cert = pdfCerts

	handler := *h
	sig.Handler = &handler
	sig.Filter = core.MakeName("Adobe.PPKLite")
	sig.SubFilter = core.MakeName("adbe.pkcs7.detached")
	sig.Reference = nil

	// reserve initial size
	return handler.Sign(sig, nil)
}

// NewDigest .
func (h *GlobalsignDSS) NewDigest(sig *model.PdfSignature) (model.Hasher, error) {
	return bytes.NewBuffer(nil), nil
}

// Sign .
func (h *GlobalsignDSS) Sign(sig *model.PdfSignature, digest model.Hasher) error {
	if digest == nil {
		sig.Contents = core.MakeHexString(string(make([]byte, sigLen)))
		return nil
	}

	buffer := digest.(*bytes.Buffer)
	signedData, err := pkcs7.NewSignedData(buffer.Bytes())
	if err != nil {
		return err
	}

	// set digest algorithm which supported by globalsign
	signedData.SetDigestAlgorithm(pkcs7.OIDDigestAlgorithmSHA256)

	// get certificate
	cert, err := h.getCertificate(sig)
	if err != nil {
		return err
	}

	if err := signedData.AddSigner(cert, globalsign.NewSigner(h.ctx, h.manager, h.signer, h.identity), pkcs7.SignerInfoConfig{}); err != nil {
		return err
	}

	// Call Detach() is you want to remove content from the signature
	// and generate an S/MIME detached signature
	signedData.Detach()
	// Finish() to obtain the signature bytes
	detachedSignature, err := signedData.Finish()
	if err != nil {
		return err
	}

	data := make([]byte, sigLen)
	copy(data, detachedSignature)

	sig.Contents = core.MakeHexString(string(data))
	return nil
}

// NewGlobalSignDSS create custom unidoc sighandler which leverage globalsign DSS service
// this handler assume that globalsign credential already have been set
// please see globalsign.SetupCredential
func NewGlobalSignDSS(ctx context.Context, m *globalsign.Manager, signer string, identity map[string]interface{}) (model.SignatureHandler, error) {
	return &GlobalsignDSS{
		ctx:      ctx,
		manager:  m,
		signer:   signer,
		identity: identity,
	}, nil
}

// InitFunc allow customize pdf signature initialization
type InitFunc func(model.SignatureHandler, *model.PdfSignature) error

// SignFunc allow customize signing implementation
type SignFunc func(model.SignatureHandler, *model.PdfSignature, model.Hasher) error

type CustomHandler struct {
	initFunc InitFunc
	signFunc SignFunc
}

// NewDigest .
func (h *CustomHandler) NewDigest(sig *model.PdfSignature) (model.Hasher, error) {
	return bytes.NewBuffer(nil), nil
}

// IsApplicable .
func (h *CustomHandler) IsApplicable(sig *model.PdfSignature) bool {
	if sig == nil || sig.Filter == nil || sig.SubFilter == nil {
		return false
	}

	return (*sig.Filter == "Adobe.PPKMS" || *sig.Filter == "Adobe.PPKLite") && *sig.SubFilter == "adbe.pkcs7.detached"
}

// InitSignature .
func (h *CustomHandler) InitSignature(sig *model.PdfSignature) error {
	if h.initFunc != nil {
		return h.initFunc(h, sig)
	}

	return nil
}

// Sign .
func (h *CustomHandler) Sign(sig *model.PdfSignature, digest model.Hasher) error {
	if h.signFunc != nil {
		return h.signFunc(h, sig, digest)
	}

	return nil
}

// Validate .
func (h *CustomHandler) Validate(sig *model.PdfSignature, digest model.Hasher) (model.SignatureValidationResult, error) {

	return model.SignatureValidationResult{
		IsSigned:   true,
		IsVerified: true,
	}, nil
}

// NewCustomHandler allow client to implement their own init and sign function
func NewCustomHandler(initFunc InitFunc, signFunc SignFunc) model.SignatureHandler {
	return &CustomHandler{
		initFunc: initFunc,
		signFunc: signFunc,
	}
}
