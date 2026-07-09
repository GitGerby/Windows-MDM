package mdm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/devauth"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func certToPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestAuthenticateDevice_RequiresVerifiedClientCert(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HWID-1")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "", "", "")

	t.Run("valid client cert authenticates", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/omadm", nil)
		req.TLS = testutil.ClientTLSState(cert)
		got, err := h.authenticateDevice(req)
		if err != nil {
			t.Fatalf("valid cert rejected: %v", err)
		}
		if got != deviceID {
			t.Fatalf("got device %q, want %q", got, deviceID)
		}
	})

	t.Run("hardware_id query param does NOT authenticate", func(t *testing.T) {
		// The removed bypass: anyone knowing a (non-secret) hardware_id could
		// previously impersonate a device with no certificate.
		req := httptest.NewRequest("POST", "/omadm?hwid=HWID-1", nil)
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("hardware_id must not authenticate without a client cert")
		}
	})

	t.Run("no certificate is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/omadm", nil)
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("request with no client cert must be rejected")
		}
	})

	t.Run("foreign (non-CA) certificate is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/omadm", nil)
		req.TLS = testutil.ClientTLSState(selfSignedCert(t))
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("certificate not chaining to our CA must be rejected")
		}
	})

	t.Run("revoked certificate is rejected", func(t *testing.T) {
		if _, err := database.Exec(db.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/omadm", nil)
		req.TLS = testutil.ClientTLSState(cert)
		if _, err := h.authenticateDevice(req); err == nil {
			t.Fatal("revoked device certificate must be rejected")
		}
	})
}

func TestAuthenticateDevice_TrustedProxyHeader(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HWID-PX")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "X-Forwarded-Client-Cert", "", "")

	// Simulate nginx $ssl_client_escaped_cert (URL-encoded PEM).
	pemStr := url.QueryEscape(string(certToPEM(cert.Raw)))
	req := httptest.NewRequest("POST", "/omadm", nil)
	req.Header.Set("X-Forwarded-Client-Cert", pemStr)
	got, err := h.authenticateDevice(req)
	if err != nil {
		t.Fatalf("trusted-proxy header cert rejected: %v", err)
	}
	if got != deviceID {
		t.Fatalf("got %q want %q", got, deviceID)
	}

	// Missing header → rejected.
	req2 := httptest.NewRequest("POST", "/omadm", nil)
	if _, err := h.authenticateDevice(req2); err == nil {
		t.Fatal("empty trusted-proxy header must be rejected")
	}
}

func TestAuthenticateDevice_ThumbprintProxyHeader(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HWID-TP")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")

	// Pre-populate the thumbprint_sha256 column so the lookup works.
	sha256TP := devauth.ThumbprintSHA256(cert)
	if _, err := database.Exec(db.Rebind(`UPDATE certificates SET thumbprint_sha256 = ? WHERE device_id = ?`), sha256TP, deviceID); err != nil {
		t.Fatalf("updating thumbprint_sha256: %v", err)
	}

	// SHA-1 thumbprint mode
	h := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "", "X-Client-Cert-Thumbprint", "sha1")
	tp := devauth.Thumbprint(cert)
	req := httptest.NewRequest("POST", "/omadm", nil)
	req.Header.Set("X-Client-Cert-Thumbprint", tp)
	got, err := h.authenticateDevice(req)
	if err != nil {
		t.Fatalf("SHA-1 thumbprint proxy rejected: %v", err)
	}
	if got != deviceID {
		t.Fatalf("got %q want %q", got, deviceID)
	}

	// SHA-256 thumbprint mode
	h256 := NewHandler(database.DB, ca.TLSPool(), "mdm.example.com", "", "X-Client-Cert-Thumbprint", "sha256")
	req256 := httptest.NewRequest("POST", "/omadm", nil)
	req256.Header.Set("X-Client-Cert-Thumbprint", sha256TP)
	got256, err := h256.authenticateDevice(req256)
	if err != nil {
		t.Fatalf("SHA-256 thumbprint proxy rejected: %v", err)
	}
	if got256 != deviceID {
		t.Fatalf("got %q want %q", got256, deviceID)
	}

	// Uppercase thumbprint should also work (normalization).
	reqUpper := httptest.NewRequest("POST", "/omadm", nil)
	reqUpper.Header.Set("X-Client-Cert-Thumbprint", strings.ToUpper(tp))
	gotUpper, err := h.authenticateDevice(reqUpper)
	if err != nil {
		t.Fatalf("uppercase thumbprint rejected: %v", err)
	}
	if gotUpper != deviceID {
		t.Fatalf("got %q want %q", gotUpper, deviceID)
	}

	// Colon-separated thumbprint should also work (HAProxy format).
	var buf strings.Builder
	for i := 0; i < len(tp); i += 2 {
		if i > 0 {
			buf.WriteByte(':')
		}
		buf.WriteString(tp[i : i+2])
	}
	reqColon := httptest.NewRequest("POST", "/omadm", nil)
	reqColon.Header.Set("X-Client-Cert-Thumbprint", buf.String())
	gotColon, err := h.authenticateDevice(reqColon)
	if err != nil {
		t.Fatalf("colon-separated thumbprint rejected: %v", err)
	}
	if gotColon != deviceID {
		t.Fatalf("got %q want %q", gotColon, deviceID)
	}

	// Empty header should be rejected.
	reqEmpty := httptest.NewRequest("POST", "/omadm", nil)
	if _, err := h.authenticateDevice(reqEmpty); err == nil {
		t.Fatal("empty thumbprint header must be rejected")
	}

	// Wrong-length thumbprint should be rejected.
	reqBadLen := httptest.NewRequest("POST", "/omadm", nil)
	reqBadLen.Header.Set("X-Client-Cert-Thumbprint", "ab12cd34")
	if _, err := h.authenticateDevice(reqBadLen); err == nil {
		t.Fatal("wrong-length thumbprint must be rejected")
	}

	// Invalid hex should be rejected.
	reqBadHex := httptest.NewRequest("POST", "/omadm", nil)
	reqBadHex.Header.Set("X-Client-Cert-Thumbprint", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
	if _, err := h.authenticateDevice(reqBadHex); err == nil {
		t.Fatal("invalid hex thumbprint must be rejected")
	}

	// Unknown thumbprint should be rejected.
	reqUnknown := httptest.NewRequest("POST", "/omadm", nil)
	reqUnknown.Header.Set("X-Client-Cert-Thumbprint", "0000000000000000000000000000000000000000")
	if _, err := h.authenticateDevice(reqUnknown); err == nil {
		t.Fatal("unknown thumbprint must be rejected")
	}

	// Revoked cert thumbprint should be rejected.
	if _, err := database.Exec(db.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
		t.Fatal(err)
	}
	reqRevoked := httptest.NewRequest("POST", "/omadm", nil)
	reqRevoked.Header.Set("X-Client-Cert-Thumbprint", tp)
	if _, err := h.authenticateDevice(reqRevoked); err == nil {
		t.Fatal("revoked thumbprint must be rejected")
	}
}

func selfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert
}
