package globalsign

import (
	"context"
	"crypto"
	"io"
)

// Signer implements custom crypto.Signer which utilize globalsign DSS API
// to sign signature digest
type Signer struct {
	// signer identification
	signedBy string

	// caller context
	ctx context.Context
}

// Public .
func (s *Signer) Public() crypto.PublicKey {
	return nil
}

// Sign request
func (s *Signer) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// get signature based on "signedBy" identification
	result, err := GetSignature(s.ctx, s.signedBy, digest)
	if err != nil {
		return nil, err
	}

	return result.Signature, nil
}

// NewSigner create crypto.Signer implementation
func NewSigner(ctx context.Context, signedBy string) crypto.Signer {
	return &Signer{
		ctx:      ctx,
		signedBy: signedBy,
	}
}
