# Active Context: Latchz MDM

## Current Focus

The project is in **Proof of Concept** stage. The core MDM enrollment flow is implemented (MS-MDE2 discovery, XCEP certificate enrollment, WSTEP token exchange, OMA-DM endpoint), and the React dashboard provides basic device management capabilities.

## Recent Changes

- Project module path: `github.com/latchzmdm/latchz` (previously referenced as "Pane" in some internal comments)
- Go version: 1.26.2 (unreleased/future Go version)
- Frontend uses Vite 8.x with React 19
- Database uses `golang-migrate` with embedded SQL migrations

## Important Patterns and Preferences

### Naming Convention
- Internal package comments still reference "Pane" in places (e.g., `// Package server sets up the HTTPS server with all routes for Pane`) — these should be updated to "Latchz"
- Config uses snake_case YAML keys with `LATCHZ_` env var prefix
- Module path uses `latchzmdm` organization

### Configuration Pattern
- Viper for config loading with priority: env vars > config file > defaults
- Explicit `BindEnv` calls for nested keys (Viper limitation workaround)
- Standard `PORT` env var support for cloud platforms

### Database Pattern
- Parameterized queries use `?` placeholders (SQLite style)
- `dbpkg.Rebind()` converts `?` to `$1, $2, ...` for PostgreSQL compatibility
- Migrations embedded via `go:embed` into the binary

### TLS Pattern
- Four modes: `auto` (Let's Encrypt), `manual`, `self-signed`, `none`
- CA key encrypted in database using AES-256-GCM with `master_secret`
- Device certificates: 1-year validity, clientAuth ExtKeyUsage only

### SOAP Protocol Handling
- MS-MDE2 requires specific XML namespace prefixes that Go's `encoding/xml` cannot produce natively
- Manual XML string replacement hack applied after marshaling to ensure protocol compliance
- SOAP responses logged to `last_soap_response.xml` for debugging

## Active Decisions

1. **Single-binary architecture** — React frontend embedded via Go `embed` directive
2. **Chi router** — chosen for simplicity and middleware support
3. **CGo-free SQLite** — using `modernc.org/sqlite` instead of `github.com/mattn/go-sqlite3`
4. **No separate auth service** — OIDC handled inline in the server

## Project Insights

- The enrollment flow is the most protocol-sensitive part — SOAP XML namespace mismatches cause enrollment failures
- The `master_secret` config value is critical: losing it means the CA key is unrecoverable
- Development uses `self-signed` TLS by default; production requires `auto` or `manual` mode
- The dashboard runs on Vite dev server separately from the Go API during development

## Next Steps

1. Complete any remaining unimplemented API endpoints (noted as `TODO` in server.go)
2. Import Microsoft DDF schemas into the policy catalog
3. Run security audit before production readiness
4. Update remaining "Pane" references to "Latchz"
5. Add integration tests for enrollment flow