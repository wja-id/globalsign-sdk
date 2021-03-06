package globalsign

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/unidoc/timestamp"
	"golang.org/x/crypto/ocsp"
)

func TestSigning(t *testing.T) {
	apiKey := os.Getenv("GLOBALSIGN_DSS_API_KEY")
	apiSecret := os.Getenv("GLOBALSIGN_DSS_API_SECRET")
	apiBaseURL := "https://emea.api.dss.globalsign.com:8443/v2"
	certPath := os.Getenv("GLOBALSIGN_DSS_CERT_PATH")
	keyPath := os.Getenv("GLOBALSIGN_DSS_KEY_PATH")

	t.Logf("Login with API key: %s and API Secret: %s", apiKey, apiSecret)
	t.Logf("Cert path: %s and key path: %s", certPath, keyPath)

	httpC, err := NewHTTPClientWithCertificate(certPath, keyPath)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	c, err := New(httpC, SetBaseURL(apiBaseURL))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	resp, httpResp, err := c.LoginService.Login(context.Background(), &LoginRequest{APIKey: apiKey, APISecret: apiSecret})
	if err != nil {
		t.Error("Login() failed with code:", httpResp.StatusCode)
		t.FailNow()
	}

	t.Logf("Access Token: %s", resp.AccessToken)
	c.SetAuthToken(resp.AccessToken)

	// get identity
	identity, httpResp, err := c.DigitalSigningService.Identity(context.Background(), &IdentityRequest{
		SubjectDn: map[string]interface{}{
			"common_name": "Galih Rivanto",
		},
	})
	if err != nil {
		t.Error(err)
		t.Error("Identity() failed with code:", httpResp.StatusCode)
		t.FailNow()
	}

	t.Logf("ID: %s", identity.ID)
	t.Logf("Signing Cert: %s", identity.SigningCert)
	t.Logf("OCSP Resp: %s", identity.OCSPResponse)

	// get certificate path
	cert, httpResp, err := c.DigitalSigningService.CertificatePath(context.Background())
	if err != nil {
		t.Error(err)
		t.Error("Certicate() failed with code:", httpResp.StatusCode)
		t.FailNow()
	}
	t.Logf("CA: %s", cert.CA)

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
			t.Error(err)
			t.FailNow()
		}

		certChain = append(certChain, issuer)
	}

	caCertData := []byte(cert.CA)
	for len(caCertData) != 0 {
		var block *pem.Block
		block, caCertData = pem.Decode(caCertData)
		if block == nil {
			break
		}

		issuer, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Error(err)
			t.FailNow()
		}

		certChain = append(certChain, issuer)
	}

	ocspDecoded, err := base64.StdEncoding.DecodeString(identity.OCSPResponse)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	ocspResponse, err := ocsp.ParseResponse(ocspDecoded, certChain[1])
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Logf("OCSP: %v", ocspResponse)

	// mock digest
	digest := sha256.Sum256([]byte(fmt.Sprintf("%x", time.Now().Unix())))

	// encode to hex
	digestHex := strings.ToUpper(hex.EncodeToString(digest[:]))

	t.Logf("Digest: %s", digestHex)

	// get timestamp
	timestampResp, httpResp, err := c.DigitalSigningService.Timestamp(context.Background(), &TimestampRequest{
		Digest: digestHex,
	})
	if err != nil {
		t.Error(err)
		t.Error("Timestamp() failed with code:", httpResp.StatusCode)
		t.FailNow()
	}
	t.Logf("Timestamp: %s", timestampResp.Token)

	decodedTs, err := base64.StdEncoding.DecodeString(timestampResp.Token)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	t.Logf("Timestamp: %s", string(decodedTs))

	tsResp, err := timestamp.Parse(decodedTs)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("Timestamp Token: %v", tsResp)

	// get signature
	signature, httpResp, err := c.DigitalSigningService.Sign(context.Background(), &SigningRequest{
		ID:     identity.ID,
		Digest: digestHex,
	})
	if err != nil {
		t.Error(err)
		t.Error("Sign() failed with code:", httpResp.StatusCode)
		t.FailNow()
	}

	t.Logf("Signature: %s", signature.Signature)

	signatureHash, err := hex.DecodeString(signature.Signature)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	t.Logf("Signature: %s", string(signatureHash))

	trustChain, _, err := c.DigitalSigningService.TrustChain(context.Background())
	if err != nil {
		t.Error(err)
		t.Error("TrusChain() failed with code:", httpResp.StatusCode)
		t.FailNow()
	}

	t.Logf("Trust Chain: %v", trustChain.Path)
}
