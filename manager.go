package globalsign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	authTokenTTL = 30 * time.Minute
	identityTTL  = 10 * time.Minute
)

// ManagerOption .
type ManagerOption struct {
	BaseURL            string
	APIKey             string
	APISecret          string
	TLSCertificatePath string
	PrivateKeyPath     string
	InsecureSkipVerify bool
}

// Valid determine whether option is valid
func (o *ManagerOption) Valid() bool {
	return o.APIKey != "" && o.APISecret != "" && o.TLSCertificatePath != "" && o.PrivateKeyPath != ""
}

// Manager .
type Manager struct {
	sync.RWMutex

	apiKey    string
	apiSecret string

	token   string
	tokenTs time.Time

	client *Client
	vault  *IdentityVault
}

// GetIdentity .
func (s *Manager) GetIdentity(ctx context.Context, signer string, req *IdentityRequest) (*DSSIdentity, error) {
	// check identity in vault
	identity, ok := s.vault.Get(signer)
	if ok {
		return identity, nil
	}

	// otherwise request new identity
	err := s.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	// request id and signing certificate
	identityResp, _, err := s.client.DigitalSigningService.Identity(ctx, req)
	if err != nil {
		return nil, err
	}

	// request cs certificate
	certResp, _, err := s.client.DigitalSigningService.CertificatePath(ctx)
	if err != nil {
		return nil, err
	}

	identity = &DSSIdentity{
		ID:          identityResp.ID,
		SigningCert: identityResp.SigningCert,
		OCSP:        identityResp.OCSPResponse,
		CA:          certResp.CA,
	}

	s.vault.Set(signer, identity)

	return identity, nil
}

// Sign .
func (s *Manager) Sign(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	log.Println("request hash")

	err := s.ensureToken(ctx)
	if err != nil {
		return nil, err
	}

	identity, err := s.GetIdentity(ctx, signer, identityReq)
	if err != nil {
		return nil, err
	}

	// encode to hex
	digestHex := strings.ToUpper(hex.EncodeToString(digest))

	signatureResp, _, err := s.client.DigitalSigningService.Sign(ctx, &SigningRequest{
		ID:     identity.ID,
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	return hex.DecodeString(signatureResp.Signature)
}

// Timestamp .
func (s *Manager) Timestamp(ctx context.Context, signer string, identityReq *IdentityRequest, digest []byte) ([]byte, error) {
	log.Println("request timestamp")

	err := s.ensureToken(ctx)
	if err != nil {
		return nil, err
	}
	// encode to hex
	digestHex := strings.ToUpper(hex.EncodeToString(digest))

	timestampResp, httpResp, err := s.client.DigitalSigningService.Timestamp(ctx, &TimestampRequest{
		Digest: digestHex,
	})
	if err != nil {
		log.Println("TS err:", httpResp.Header)
		return nil, err
	}

	return base64.StdEncoding.DecodeString(timestampResp.Token)
}

// ensure token valid
func (s *Manager) ensureToken(ctx context.Context) error {
	s.RLock()
	token := s.token
	tokenTs := s.tokenTs
	s.RUnlock()

	// if token not yet acquired or expired
	if token == "" || time.Since(tokenTs) > authTokenTTL {
		resp, _, err := s.client.LoginService.Login(ctx, &LoginRequest{
			APIKey:    s.apiKey,
			APISecret: s.apiSecret,
		})
		if err != nil {
			return err
		}

		s.Lock()
		s.token = resp.AccessToken
		s.tokenTs = time.Now()
		s.client.SetAuthToken(s.token)
		s.Unlock()
	}

	return nil
}

// NewManager is a wrapper for client and
func NewManager(option *ManagerOption) (*Manager, error) {
	if !option.Valid() {
		return nil, errors.New("option is not valid")
	}

	// create a client
	httpClient, err := NewHTTPClientWithCertificate(option.TLSCertificatePath, option.PrivateKeyPath, option.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}

	client, err := New(httpClient, SetBaseURL(option.BaseURL))
	if err != nil {
		return nil, err
	}

	return &Manager{
		apiKey:    option.APIKey,
		apiSecret: option.APISecret,
		client:    client,
		vault:     NewIdentityVault(identityTTL),
	}, nil
}
