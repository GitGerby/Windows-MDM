// Package devauth resolves an enrolled device from its client certificate. It is
// the single source of truth for "given an HTTP request, which non-revoked
// device cert is presenting it" — used by the OMA-DM endpoint (device check-in)
// and by WSTEP certificate renewal, so both paths apply identical trust rules.
package devauth

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	dbpkg "github.com/latchzmdm/latchz/internal/db"
)

// Identity is the resolved device behind a client certificate.
type Identity struct {
	DeviceID   string
	EnrolledBy string
}

// Thumbprint is the canonical certificate fingerprint used for DB lookups
// (lowercase hex SHA-1 of the DER). It MUST stay in sync with the format used
// when storing certificates (pki stores the same lowercase-hex SHA-1).
func Thumbprint(cert *x509.Certificate) string {
	sum := sha1.Sum(cert.Raw)
	return fmt.Sprintf("%x", sum[:])
}

// ThumbprintSHA256 returns the lowercase-hex SHA-256 fingerprint of the
// DER-encoded certificate. Used when the reverse proxy forwards a SHA-256
// thumbprint instead of the full certificate.
func ThumbprintSHA256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", sum[:])
}

// NormalizeThumbprint strips colons, spaces, and case-normalizes a
// hex-encoded thumbprint to lowercase. Handles formats from nginx, HAProxy,
// Apache, and other common reverse proxies.
func NormalizeThumbprint(raw string) string {
	s := strings.ReplaceAll(raw, ":", "")
	s = strings.ReplaceAll(s, " ", "")
	return strings.ToLower(s)
}

// ClientCert extracts the presented client certificate from the TLS peer chain
// or, when proxyHeader is non-empty, from a header set by a trusted terminating
// proxy (URL-encoded or raw PEM). Returns an error if none is present.
func ClientCert(r *http.Request, proxyHeader string) (*x509.Certificate, error) {
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return r.TLS.PeerCertificates[0], nil
	}
	if proxyHeader != "" {
		raw := r.Header.Get(proxyHeader)
		if raw == "" {
			return nil, fmt.Errorf("client certificate required: trusted-proxy header %q is empty", proxyHeader)
		}
		return parseProxyClientCert(raw)
	}
	return nil, fmt.Errorf("client certificate required")
}

// Resolve authenticates a device by its client certificate: the cert must chain
// to caPool and map to a non-revoked device certificate. There is no
// hardware-ID fallback (a hardware_id is not a secret).
func Resolve(db *sql.DB, caPool *x509.CertPool, r *http.Request, proxyHeader string) (*Identity, error) {
	cert, err := ClientCert(r, proxyHeader)
	if err != nil {
		return nil, err
	}
	if caPool == nil {
		return nil, fmt.Errorf("no CA configured for device authentication")
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("client certificate does not chain to our CA: %w", err)
	}

	id := &Identity{}
	err = db.QueryRow(dbpkg.Rebind(`
		SELECT c.device_id, COALESCE(d.enrolled_by, '')
		FROM certificates c
		JOIN devices d ON d.id = c.device_id
		WHERE c.thumbprint = ? AND c.cert_type = 'device' AND c.revoked = 0
	`), Thumbprint(cert)).Scan(&id.DeviceID, &id.EnrolledBy)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("no active device for certificate thumbprint %s (revoked or unknown)", Thumbprint(cert))
	}
	if err != nil {
		return nil, fmt.Errorf("database error looking up device: %w", err)
	}
	return id, nil
}

// ResolveByThumbprint authenticates a device using only a certificate
// thumbprint forwarded by a trusted terminating proxy. Unlike Resolve(), this
// does NOT verify the certificate chains to a CA (the proxy is trusted to have
// performed that validation). The thumbprint is normalized and compared against
// stored thumbprints in the database.
//
// algorithm must be "sha1" or "sha256" and must match what the proxy uses.
func ResolveByThumbprint(db *sql.DB, r *http.Request, headerName string, algorithm string) (*Identity, error) {
	raw := r.Header.Get(headerName)
	if raw == "" {
		return nil, fmt.Errorf("client certificate thumbprint required: trusted-proxy header %q is empty", headerName)
	}

	thumbprint := NormalizeThumbprint(raw)

	switch strings.ToLower(algorithm) {
	case "sha1":
		if len(thumbprint) != 40 {
			return nil, fmt.Errorf("invalid SHA-1 thumbprint length: got %d chars, want 40", len(thumbprint))
		}
	case "sha256":
		if len(thumbprint) != 64 {
			return nil, fmt.Errorf("invalid SHA-256 thumbprint length: got %d chars, want 64", len(thumbprint))
		}
	default:
		return nil, fmt.Errorf("unsupported thumbprint algorithm: %q (must be sha1 or sha256)", algorithm)
	}

	// Validate thumbprint is valid hex
	for _, c := range thumbprint {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return nil, fmt.Errorf("invalid hex character in thumbprint: %q", c)
		}
	}

	id := &Identity{}
	switch strings.ToLower(algorithm) {
	case "sha1":
		err := db.QueryRow(dbpkg.Rebind(`
			SELECT c.device_id, COALESCE(d.enrolled_by, '')
			FROM certificates c
			JOIN devices d ON d.id = c.device_id
			WHERE c.thumbprint = ? AND c.cert_type = 'device' AND c.revoked = 0
		`), thumbprint).Scan(&id.DeviceID, &id.EnrolledBy)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no active device for certificate thumbprint %s (revoked or unknown)", thumbprint)
		}
		if err != nil {
			return nil, fmt.Errorf("database error looking up device: %w", err)
		}
	case "sha256":
		err := db.QueryRow(dbpkg.Rebind(`
			SELECT c.device_id, COALESCE(d.enrolled_by, '')
			FROM certificates c
			JOIN devices d ON d.id = c.device_id
			WHERE c.thumbprint_sha256 = ? AND c.cert_type = 'device' AND c.revoked = 0
		`), thumbprint).Scan(&id.DeviceID, &id.EnrolledBy)
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("no active device for certificate SHA-256 thumbprint %s (revoked or unknown)", thumbprint)
		}
		if err != nil {
			return nil, fmt.Errorf("database error looking up device: %w", err)
		}
	}
	return id, nil
}

// parseProxyClientCert decodes a client certificate forwarded by a terminating
// proxy. It accepts a raw PEM string or a URL-encoded PEM (e.g. nginx
// $ssl_client_escaped_cert). The raw form is tried first so base64 '+' chars
// are not mangled by URL-decoding.
func parseProxyClientCert(raw string) (*x509.Certificate, error) {
	candidates := []string{raw}
	if decoded, err := url.QueryUnescape(raw); err == nil && decoded != raw {
		candidates = append(candidates, decoded)
	}
	for _, c := range candidates {
		block, _ := pem.Decode([]byte(c))
		if block == nil {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			return cert, nil
		}
	}
	return nil, fmt.Errorf("trusted-proxy client cert header is not a valid certificate")
}