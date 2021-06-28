package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"time"

	"github.com/unidoc/unipdf/v3/annotator"
	"github.com/unidoc/unipdf/v3/core"
	"github.com/unidoc/unipdf/v3/model"
)

// SignOption contains both digital signing
// and annotation properties
type SignOption struct {
	SignedBy string
	Fullname string
	Reason   string
	Location string

	// Annonate signature?
	Annotate bool

	// position of annotation
	Position []float64

	// Annotation font size
	FontSize int

	// extra signature annotation fields
	Extra map[string]string

	FilePath string

	// just in case source file is protected
	// and defalt password is not empty
	Password string
}

func defaultSignOption() *SignOption {
	return &SignOption{
		FontSize: 11,
	}
}

// generateSignedFile generates a signed version of the input PDF file using the
// specified signature handler.
func generateSignedFile(inputPath string, handler model.SignatureHandler, option *SignOption) ([]byte, *model.PdfSignature, error) {
	if option == nil {
		option = defaultSignOption()
	}

	// generate timestamp
	now := time.Now()

	// Create reader.
	file, err := os.Open(inputPath)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()

	reader, err := model.NewPdfReader(file)
	if err != nil {
		return nil, nil, err
	}

	// Create pdf appender.
	appender, err := model.NewPdfAppender(reader)
	if err != nil {
		return nil, nil, err
	}

	// Create signature.
	signature := model.NewPdfSignature(handler)
	signature.SetName(option.SignedBy)
	signature.SetReason(option.Reason)
	signature.SetDate(now, time.RFC1123)
	signature.SetLocation(option.Location)

	if err := signature.Initialize(); err != nil {
		return nil, nil, err
	}

	// Create signature field and appearance.
	var field *model.PdfFieldSignature

	// onyl when annotate option is enabled
	if option.Annotate {
		opts := annotator.NewSignatureFieldOpts()
		opts.FontSize = 10

		// set default position
		opts.Rect = []float64{10, 25, 75, 60}
		if option.Position != nil && len(option.Position) == 4 {
			opts.Rect = option.Position
		}

		signatureFields := []*annotator.SignatureLine{
			annotator.NewSignatureLine("Signed By", option.SignedBy),
			annotator.NewSignatureLine("Date", now.Format(time.RFC1123)),
			annotator.NewSignatureLine("Reason", option.Reason),
			annotator.NewSignatureLine("Location", option.Location),
		}

		for k, v := range option.Extra {
			signatureFields = append(signatureFields, annotator.NewSignatureLine(k, v))
		}

		field, err = annotator.NewSignatureField(
			signature,
			signatureFields,
			opts,
		)
		field.T = core.MakeString("Signature")
	}

	if err = appender.Sign(1, field); err != nil {
		return nil, nil, err
	}

	// Write PDF file to buffer.
	pdfBuf := bytes.NewBuffer(nil)
	if err = appender.Write(pdfBuf); err != nil {
		return nil, nil, err
	}

	return pdfBuf.Bytes(), signature, nil
}

// SignerFactory .
type SignerFactory func(map[string]interface{}) Signer

var signerFactories = make(map[string]SignerFactory)

// CreateSigner .
func CreateSigner(signerType string, param map[string]interface{}) Signer {
	factory, ok := signerFactories[signerType]
	if !ok {
		return nil
	}

	return factory(param)
}

// Sign apply digital signing from inputFile to outputFile
// with signature generator callback
func SignFile(ctx context.Context, inputFile, outputFile string, option *SignOption, signer Signer) error {

	fin, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer fin.Close()

	rd, err := model.NewPdfReader(fin)
	if err != nil {
		return err
	}

	ap, err := Sign(ctx, rd, option, signer)
	if err != nil {
		return err
	}

	fout, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer fout.Close()

	return ap.Write(fout)
}

// Sign apply digital signing to given pdf reader which return pdf appender
func Sign(ctx context.Context, rd *model.PdfReader, option *SignOption, signer Signer) (*model.PdfAppender, error) {
	if signer == nil {
		return nil, errors.New("signer not provided")
	}

	if err := signer.Load(); err != nil {
		return nil, err
	}

	if option == nil {
		option = defaultSignOption()
	}

	return signer.Sign(ctx, rd, option)
}

// Signer abstract pdf signer implementation
type Signer interface {
	// Load init and prepare signer
	// it may fail on bad configuration
	Load() error

	// Sign .
	Sign(context.Context, *model.PdfReader, *SignOption) (*model.PdfAppender, error)
}
