package devauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	idb "github.com/latchzmdm/latchz/internal/db"
	"github.com/latchzmdm/latchz/internal/testutil"
)

func TestResolve(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-DA")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")
	pool := ca.TLSPool()

	t.Run("direct mTLS resolves to the device", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.TLS = testutil.ClientTLSState(cert)
		id, err := Resolve(database.DB, pool, req, "")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("Resolve = (%+v, %v), want device %q", id, err, deviceID)
		}
		if id.EnrolledBy != "seed@test" {
			t.Fatalf("EnrolledBy = %q", id.EnrolledBy)
		}
	})

	t.Run("trusted-proxy header resolves to the device", func(t *testing.T) {
		pemStr := url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})))
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Forwarded-Client-Cert", pemStr)
		id, err := Resolve(database.DB, pool, req, "X-Forwarded-Client-Cert")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("proxy-header Resolve = (%+v, %v)", id, err)
		}
	})

	t.Run("no certificate is rejected", func(t *testing.T) {
		if _, err := Resolve(database.DB, pool, httptest.NewRequest("POST", "/x", nil), ""); err == nil {
			t.Fatal("expected rejection without a client cert")
		}
	})

	t.Run("foreign cert is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.TLS = testutil.ClientTLSState(selfSigned(t))
		if _, err := Resolve(database.DB, pool, req, ""); err == nil {
			t.Fatal("expected rejection of a cert not chaining to our CA")
		}
	})

	t.Run("revoked cert is rejected", func(t *testing.T) {
		if _, err := database.Exec(idb.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/x", nil)
		req.TLS = testutil.ClientTLSState(cert)
		if _, err := Resolve(database.DB, pool, req, ""); err == nil {
			t.Fatal("expected rejection of a revoked cert")
		}
	})
}

// ── NormalizeThumbprint tests ─────────────────────────────────────────

func TestNormalizeThumbprint(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"nginx sha1 uppercase", "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12", "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"},
		{"haproxy colon separated", "ab:12:cd:34:ef:56:ab:12:cd:34:ef:56:ab:12:cd:34:ef:56:ab:12", "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"},
		{"already lowercase no separators", "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12", "ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12"},
		{"with spaces", "ab 12 cd 34 ef 56", "ab12cd34ef56"},
		{"mixed case with colons", "AB:12:cd:34", "ab12cd34"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeThumbprint(tt.input)
			if got != tt.expected {
				t.Errorf("NormalizeThumbprint(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// ── ThumbprintSHA256 tests ─────────────────────────────────────────────

func TestThumbprintSHA256(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-SHA256")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")

	tp := ThumbprintSHA256(cert)

	// Must be 64 lowercase hex chars.
	if len(tp) != 64 {
		t.Fatalf("ThumbprintSHA256 length = %d, want 64", len(tp))
	}
	for _, c := range tp {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("ThumbprintSHA256 contains non-hex char %q", c)
		}
	}

	// Must match manual computation.
	want := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
	if tp != want {
		t.Fatalf("ThumbprintSHA256 = %q, want %q", tp, want)
	}
}

// ── ResolveByThumbprint tests ──────────────────────────────────────────

func TestResolveByThumbprint(t *testing.T) {
	database := testutil.DB(t)
	ca := testutil.CA(t, database)
	deviceID := testutil.SeedDevice(t, database, "HW-RBT")
	cert := testutil.IssueClientCert(t, ca, deviceID, "PaneMDMClient")

	// Pre-populate the thumbprint_sha256 column so SHA-256 lookups work.
	sha256TP := ThumbprintSHA256(cert)
	if _, err := database.Exec(idb.Rebind(`UPDATE certificates SET thumbprint_sha256 = ? WHERE device_id = ?`), sha256TP, deviceID); err != nil {
		t.Fatalf("updating thumbprint_sha256: %v", err)
	}

	t.Run("sha1 thumbprint resolves device", func(t *testing.T) {
		tp := Thumbprint(cert)
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", tp)
		id, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("ResolveByThumbprint SHA-1 = (%+v, %v), want device %q", id, err, deviceID)
		}
	})

	t.Run("sha256 thumbprint resolves device", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", sha256TP)
		id, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha256")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("ResolveByThumbprint SHA-256 = (%+v, %v), want device %q", id, err, deviceID)
		}
	})

	t.Run("uppercase thumbprint is normalized", func(t *testing.T) {
		tp := strings.ToUpper(Thumbprint(cert))
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", tp)
		id, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("uppercase thumbprint should resolve: %v", err)
		}
	})

	t.Run("colon-separated thumbprint is normalized", func(t *testing.T) {
		tp := Thumbprint(cert)
		var buf strings.Builder
		for i := 0; i < len(tp); i += 2 {
			if i > 0 {
				buf.WriteByte(':')
			}
			buf.WriteString(tp[i : i+2])
		}
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", buf.String())
		id, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err != nil || id.DeviceID != deviceID {
			t.Fatalf("colon-separated thumbprint should resolve: %v", err)
		}
	})

	t.Run("empty header is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err == nil {
			t.Fatal("expected error for empty thumbprint header")
		}
	})

	t.Run("wrong-length SHA-1 thumbprint is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", "ab12cd34")
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err == nil {
			t.Fatal("expected error for wrong-length SHA-1 thumbprint")
		}
	})

	t.Run("wrong-length SHA-256 thumbprint is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", "ab12cd34")
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha256")
		if err == nil {
			t.Fatal("expected error for wrong-length SHA-256 thumbprint")
		}
	})

	t.Run("invalid hex is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ")
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err == nil {
			t.Fatal("expected error for invalid hex thumbprint")
		}
	})

	t.Run("unknown thumbprint is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", "0000000000000000000000000000000000000000")
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err == nil {
			t.Fatal("expected error for unknown thumbprint")
		}
	})

	t.Run("revoked cert thumbprint is rejected", func(t *testing.T) {
		tp := Thumbprint(cert)
		_, _ = database.Exec(idb.Rebind(`UPDATE certificates SET revoked = 1 WHERE device_id = ?`), deviceID)
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", tp)
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "sha1")
		if err == nil {
			t.Fatal("expected error for revoked cert thumbprint")
		}
	})

	t.Run("unsupported algorithm is rejected", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/x", nil)
		req.Header.Set("X-Client-Cert-Thumbprint", Thumbprint(cert))
		_, err := ResolveByThumbprint(database.DB, req, "X-Client-Cert-Thumbprint", "md5")
		if err == nil {
			t.Fatal("expected error for unsupported algorithm")
		}
	})
}

func selfSigned(t *testing.T) *x509.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rogue"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	cert, _ := x509.ParseCertificate(der)
	return cert
}
