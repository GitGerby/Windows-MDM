-- Add SHA-256 thumbprint column to certificates table for reverse proxy thumbprint auth.
ALTER TABLE certificates ADD COLUMN thumbprint_sha256 TEXT;