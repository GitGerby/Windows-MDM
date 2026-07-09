-- Remove SHA-256 thumbprint column from certificates table.
ALTER TABLE certificates DROP COLUMN thumbprint_sha256;