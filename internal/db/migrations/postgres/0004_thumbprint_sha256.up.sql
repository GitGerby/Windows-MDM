-- Add SHA-256 thumbprint column to certificates table for reverse proxy thumbprint auth.
ALTER TABLE certificates ADD COLUMN thumbprint_sha256 TEXT;

-- Backfill existing certificates by computing SHA-256 from cert_pem.
-- Strip PEM headers/newlines, decode base64 to DER, then hash.
UPDATE certificates
SET thumbprint_sha256 = LOWER(
    encode(
        digest(
            replace(
                replace(
                    replace(
                        cert_pem,
                        '-----BEGIN CERTIFICATE-----', ''
                    ),
                    '-----END CERTIFICATE-----', ''
                ),
                E'\n', ''
            )::bytea
        ),
        'sha256'
    )
)
WHERE thumbprint_sha256 IS NULL AND cert_type = 'device';