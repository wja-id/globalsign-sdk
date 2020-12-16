package globalsign

import (
	"context"
	"errors"
	"net/http"
)

// errors definition
var (
	ErrDigestRequired = errors.New("file digest required")
)

// IdentityRequest .
type IdentityRequest struct {
	SubjectDn map[string]interface{} `json:"subject_dn"`
}

// IdentityResponse .
type IdentityResponse struct {
	ID           string `json:"id"`
	SigningCert  string `json:"signing_cert"`
	OCSPResponse string `json:"ocsp_response"`
}

// TimestampRequest .
type TimestampRequest struct {
	Digest string `json:"digest"`
}

// TimestampResponse .
type TimestampResponse struct {
	Token string `json:"token"`
}

// SigningRequest .
type SigningRequest struct {
	ID string `json:"id"`

	// a hex encoded sha256 checksum for source file
	Digest string `json:"digest"`
}

// SigningResponse .
type SigningResponse struct {
	Signature string `json:"signature"`
}

// CertificateResponse .
type CertificateResponse struct {
	CA string `json:"path"`
}

// DigitalSigningService .
type DigitalSigningService interface {
	Identity(context.Context, *IdentityRequest) (*IdentityResponse, *Response, error)
	Timestamp(context.Context, *TimestampRequest) (*TimestampResponse, *Response, error)
	Sign(context.Context, *SigningRequest) (*SigningResponse, *Response, error)
	CertificatePath(context.Context) (*CertificateResponse, *Response, error)
}

type digitalSigningService struct {
	client *Client
}

func (s *digitalSigningService) Identity(ctx context.Context, req *IdentityRequest) (*IdentityResponse, *Response, error) {
	path := baseAPI + "/identity"
	r, err := s.client.NewRequest(ctx, http.MethodPost, path, req)
	if err != nil {
		return nil, nil, err
	}

	result := new(IdentityResponse)
	resp, err := s.client.Do(ctx, r, result)
	if err != nil {
		return nil, resp, err
	}

	return result, resp, nil
}

func (s *digitalSigningService) Timestamp(ctx context.Context, req *TimestampRequest) (*TimestampResponse, *Response, error) {
	if req == nil {
		return nil, nil, ErrDigestRequired
	}

	path := baseAPI + "/timestamp/" + req.Digest
	r, err := s.client.NewRequest(ctx, http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, nil, err
	}

	result := new(TimestampResponse)
	resp, err := s.client.Do(ctx, r, result)
	if err != nil {
		return nil, resp, err
	}

	return result, resp, nil
}

func (s *digitalSigningService) Sign(ctx context.Context, req *SigningRequest) (*SigningResponse, *Response, error) {
	if req == nil {
		return nil, nil, ErrDigestRequired
	}

	path := baseAPI + "/identity/" + req.ID + "/sign/" + req.Digest
	r, err := s.client.NewRequest(ctx, http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, nil, err
	}

	result := new(SigningResponse)
	resp, err := s.client.Do(ctx, r, result)
	if err != nil {
		return nil, resp, err
	}

	return result, resp, nil
}

func (s *digitalSigningService) CertificatePath(ctx context.Context) (*CertificateResponse, *Response, error) {
	path := baseAPI + "/certificate_path"
	r, err := s.client.NewRequest(ctx, http.MethodGet, path, struct{}{})
	if err != nil {
		return nil, nil, err
	}

	result := new(CertificateResponse)
	resp, err := s.client.Do(ctx, r, result)
	if err != nil {
		return nil, resp, err
	}

	return result, resp, nil
}
