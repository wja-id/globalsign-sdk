package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"github.com/unidoc/unipdf/v3/annotator"
	"github.com/unidoc/unipdf/v3/core"
	pdf "github.com/unidoc/unipdf/v3/model"
)

// default tool creator information
var (
	ToolCreatorInfo = "pdf-signer"
	ToolAuthorInfo  = "pdf-signer"
)

func init() {
	UpdateInfo(ToolCreatorInfo, ToolAuthorInfo)
}

// UpdateInfo set tool author info for created pdf
func UpdateInfo(author, creator string) {
	pdf.SetPdfAuthor(author)
	pdf.SetPdfCreator(creator)
}

// parseByteRange parses the ByteRange value of the signature field.
func parseByteRange(byteRange *core.PdfObjectArray) ([]int64, error) {
	if byteRange == nil {
		return nil, errors.New("byte range cannot be nil")
	}
	if byteRange.Len() != 4 {
		return nil, errors.New("invalid byte range length")
	}

	s1, err := core.GetNumberAsInt64(byteRange.Get(0))
	if err != nil {
		return nil, errors.New("invalid byte range value")
	}
	l1, err := core.GetNumberAsInt64(byteRange.Get(1))
	if err != nil {
		return nil, errors.New("invalid byte range value")
	}

	s2, err := core.GetNumberAsInt64(byteRange.Get(2))
	if err != nil {
		return nil, errors.New("invalid byte range value")
	}
	l2, err := core.GetNumberAsInt64(byteRange.Get(3))
	if err != nil {
		return nil, errors.New("invalid byte range value")
	}

	return []int64{s1, s1 + l1, s2, s2 + l2}, nil
}

// GenerateChecksum returns checksum of a reader,
// reader seek head will be returned to 0 (beginning of file)
func GenerateChecksum(r io.ReadSeeker) []byte {
	bufferedReader := bufio.NewReader(r)
	computedChecksum := sha256.New()
	_, err := bufferedReader.WriteTo(computedChecksum)
	defer r.Seek(0, io.SeekStart)
	if err != nil {
		return make([]byte, 0)
	}

	return computedChecksum.Sum(nil)
}

func loadPrivateKey(privateKeyData string) (*rsa.PrivateKey, error) {
	// Decode PEM block.
	block, _ := pem.Decode([]byte(privateKeyData))

	// Parse private key data.
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func loadCertificates(certData string) (*x509.Certificate, *core.PdfObjectArray, error) {
	parseCert := func(data []byte) (*x509.Certificate, []byte, error) {
		// Decode PEM block.
		block, rest := pem.Decode(data)

		// Parse certificate.
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, err
		}

		return cert, rest, nil
	}

	// Create PDF array object which will contain the certificate chain data,
	// loaded from the PEM file. The first element of the array must be the
	// signing certificate. The rest of the certificate chain is used for
	// validating the authenticity of the signing certificate.
	pdfCerts := core.MakeArray()

	// Parse signing certificate.
	signingCert, pemUnparsedData, err := parseCert([]byte(certData))
	if err != nil {
		return nil, nil, err
	}
	pdfCerts.Append(core.MakeString(string(signingCert.Raw)))

	// Parse the rest of the certificates contained in the PEM file,
	// if any, and add them to the PDF certificates array.
	for len(pemUnparsedData) != 0 {
		cert, rest, err := parseCert(pemUnparsedData)
		if err != nil {
			return nil, nil, err
		}

		pdfCerts.Append(core.MakeString(string(cert.Raw)))
		pemUnparsedData = rest
	}

	return signingCert, pdfCerts, nil
}

func createSignatureField(option *SignOption, handler pdf.SignatureHandler, certChain ...*x509.Certificate) (*pdf.PdfFieldSignature, error) {
	// Create signature.
	signature := pdf.NewPdfSignature(handler)

	if len(certChain) > 0 {
		// Create PDF array object which will contain the certificate chain data,
		// The first element of the array must be the signing certificate.
		// The rest of the certificate chain is used for validating the authenticity
		// of the signing certificate.
		pdfCerts := core.MakeArray()
		for _, cert := range certChain {
			pdfCerts.Append(core.MakeString(string(cert.Raw)))
		}

		signature.Cert = pdfCerts
	}

	if err := signature.Initialize(); err != nil {
		return nil, err
	}

	now := time.Now()
	signature.SetName(option.Fullname)
	signature.SetReason(option.Reason)
	signature.SetDate(now, "D:20060102150405-07'00'")
	signature.SetLocation(option.Location)

	// Create signature field and appearance.
	signatureFields := make([]*annotator.SignatureLine, 0)
	opts := annotator.NewSignatureFieldOpts()

	// onyl when annotate option is enabled
	if option.Annotate {
		if option.FontSize > 0 {
			opts.FontSize = float64(option.FontSize)
		}

		// set default position
		opts.Rect = []float64{10, 25, 75, 60}
		if option.Position != nil && len(option.Position) == 4 {
			opts.Rect = option.Position
		}

		signatureFields = append(signatureFields,
			annotator.NewSignatureLine("Signed By", option.Fullname),
			annotator.NewSignatureLine("Date", now.Format(time.RFC1123)),
			annotator.NewSignatureLine("Reason", option.Reason),
			annotator.NewSignatureLine("Location", option.Location),
		)

		for k, v := range option.Extra {
			signatureFields = append(signatureFields, annotator.NewSignatureLine(k, v))
		}
	}

	field, err := annotator.NewSignatureField(
		signature,
		signatureFields,
		opts,
	)
	if err != nil {
		return nil, err
	}

	field.T = core.MakeString("Signature")

	return field, nil
}
