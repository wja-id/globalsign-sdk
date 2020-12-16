package globalsign

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"log"
	"strings"
	"sync"
	"time"
)

const (
	identityExpiration = 8 * time.Minute
)

// required credentials info
var (
	apiBase      string
	apiKey       string
	apiSecret    string
	certFilePath string
	keyFilePath  string
)

// retrieved DSS identity
var (
	identityMap = make(map[string]*DSSIdentity)

	lock sync.Mutex
)

// SetupCredential set required credential
// to communicate with globalsign DSS
func SetupCredential(url, key, secret, certFile, keyFile string) {
	apiBase = url
	apiKey = key
	apiSecret = secret
	certFilePath = certFile
	keyFilePath = keyFile
}

// DSSIdentity represent acquired credential
// from login and identity request
type DSSIdentity struct {
	// access token
	Token string

	// Identity
	Identity *IdentityResponse

	Certificate string

	Ts time.Time
}

// GetIdentity .
// TODO (galihrivanto): switch to sync.Map to prevent lock contention while
// requesting globalsign identity
func GetIdentity(ctx context.Context, name string) (*DSSIdentity, error) {
	lock.Lock()
	defer lock.Unlock()

	// acquire or renew identity
	identity, found := identityMap[name]
	if !found || identity == nil || time.Now().Sub(identity.Ts) > identityExpiration {
		log.Println("fetch identity from server")
		httpC, err := NewHTTPClientWithCertificate(certFilePath, keyFilePath)
		if err != nil {
			return nil, err
		}

		c, err := New(httpC, SetBaseURL(apiBase))
		if err != nil {
			return nil, err
		}

		loginResp, _, err := c.LoginService.Login(ctx, &LoginRequest{APIKey: apiKey, APISecret: apiSecret})
		if err != nil {
			return nil, err
		}
		c.SetAuthToken(loginResp.AccessToken)

		identityResp, _, err := c.DigitalSigningService.Identity(ctx, &IdentityRequest{
			SubjectDn: map[string]interface{}{
				"common_name": name,
			},
		})
		if err != nil {
			return nil, err
		}

		certificatePathResp, _, err := c.DigitalSigningService.CertificatePath(ctx)
		if err != nil {
			return nil, err
		}

		identity = &DSSIdentity{
			Token:       loginResp.AccessToken,
			Identity:    identityResp,
			Certificate: certificatePathResp.CA,
			Ts:          time.Now(),
		}

		identityMap[name] = identity
	}

	return identity, nil
}

// TimestampSignature contains encoded timestamp and signature
// received from globalsign DSS service
type TimestampSignature struct {
	TimestampToken []byte
	Signature      []byte
}

// GetSignature acquire signture from global sign
func GetSignature(ctx context.Context, signedBy string, digest []byte) (*TimestampSignature, error) {
	identity, err := GetIdentity(ctx, signedBy)
	if err != nil {
		return nil, err
	}

	httpC, err := NewHTTPClientWithCertificate(certFilePath, keyFilePath)
	if err != nil {
		return nil, err
	}

	c, err := New(httpC, SetBaseURL(apiBase))
	if err != nil {
		return nil, err
	}
	c.SetAuthToken(identity.Token)

	// encode to hex
	digestHex := strings.ToUpper(hex.EncodeToString(digest))

	// get timestamp
	timestampResult, _, err := c.DigitalSigningService.Timestamp(ctx, &TimestampRequest{
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	timestamp, err := base64.StdEncoding.DecodeString(timestampResult.Token)
	if err != nil {
		return nil, err
	}

	signatureResult, _, err := c.DigitalSigningService.Sign(ctx, &SigningRequest{
		ID:     identity.Identity.ID,
		Digest: digestHex,
	})
	if err != nil {
		return nil, err
	}

	signature, err := hex.DecodeString(signatureResult.Signature)
	if err != nil {
		return nil, err
	}

	return &TimestampSignature{
		TimestampToken: timestamp,
		Signature:      signature,
	}, nil
}
