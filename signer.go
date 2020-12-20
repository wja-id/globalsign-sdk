package globalsign

import (
	"context"
	"crypto"
	"io"
)

// Signer implements custom crypto.Signer which utilize globalsign DSS API
// to sign signature digest
type Signer struct {
	manager *Manager

	// signer identification
	signer   string
	identity map[string]interface{}

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
	result, err := s.manager.Sign(s.ctx, s.signer, &IdentityRequest{SubjectDn: s.identity}, digest)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// NewSigner create crypto.Signer implementation
func NewSigner(ctx context.Context, m *Manager, signer string, identity map[string]interface{}) crypto.Signer {
	return &Signer{
		ctx:      ctx,
		manager:  m,
		signer:   signer,
		identity: identity,
	}
}
