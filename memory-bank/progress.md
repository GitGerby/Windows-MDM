# Progress: Latchz MDM

## What Works

### Backend
- [x] **Configuration system** — YAML config, environment variables, defaults via Viper
- [x] **Database layer** — SQLite and PostgreSQL support with embedded migrations
- [x] **PKI / CA** — Root CA generation, device certificate issuance, key encryption (AES-256-GCM)
- [x] **MS-MDE2 enrollment** — SOAP discovery service at `/EnterpriseEnrollment/Enrollment.svc`
- [x] **MS-XCEP** — Certificate enrollment protocol at `/xcep`
- [x] **MS-WSTEP** — Web Services-Enhanced Simplified Token Exchange at `/wstep`
- [x] **OMA-DM endpoint** — SyncML handler at `/omadm`
- [x] **OIDC authentication** — Dashboard login via Google Workspace, Entra ID, etc.
- [x] **REST API** — Devices, profiles, groups, compliance, catalog endpoints
- [x] **TLS modes** — Auto (Let's Encrypt), manual, self-signed, none
- [x] **Emergency access** — Rescue endpoint for admin lockout
- [x] **Graceful shutdown** — Signal handling with context timeout

### Frontend
- [x] **React dashboard** — Glassmorphism-styled UI
- [x] **Vite dev server** — Hot module replacement during development
- [x] **Embedded binary** — React build compiled into Go binary

## What's Left to Build

### High Priority
1. **DDF ingestion** — Python script to import Microsoft DDF schemas into `policy_catalog` table
2. **OMA-DM policy enforcement** — Full SyncML command/response handling for policy push
3. **Device sync commands** — Implement actual OMA-DM sync operations for lock/wipe
4. **Dashboard completeness** — Verify all API endpoints have corresponding UI components

### Medium Priority
5. **Integration tests** — End-to-end enrollment flow tests
6. **Unit tests** — Coverage for PKI, enrollment protocol handlers, config validation
7. **Production Docker image** — Multi-stage build optimization
8. **Migration tests** — Verify SQLite ↔ PostgreSQL migration compatibility
9. **Health check endpoint** — `/api/system/health` with DB and TLS status

### Low Priority
10. **Audit logging** — Track admin actions and device events
11. **Notification system** — Email/webhook on device enrollment or compliance failure
12. **Backup/restore** — Database backup functionality
13. **Multi-domain support** — Handle multiple enrollment domains
14. **Documentation** — Setup guide, API reference, protocol documentation

## Current Status

**Version:** POC / Work in Progress  
**Database:** Schema initialized, migrations embedded  
**CA:** Auto-generated on first run, encrypted in DB  
**API:** All endpoints registered, some may be stubs  
**Dashboard:** Basic UI with device management  

## Known Issues

1. **"Pane" naming** — Internal package comments still reference "Pane" instead of "Latchz"
2. **DDF catalog empty** — No Microsoft DDF schemas imported yet (requires external Python script)
3. **No production testing** — Enrollment flow not tested against real Windows devices
4. **Security audit pending** — Encryption, auth flows, and protocol handling not independently reviewed
5. **Breaking changes expected** — API and protocol implementations may change before stable release

## Evolution of Project Decisions

| Decision | Rationale |
|----------|-----------|
| Go backend over Rust/Python | Ecosystem maturity, crypto libraries, deployment simplicity |
| Chi router over Gin/Echo | Minimalism, no framework coupling, standard library compatibility |
| CGo-free SQLite | Simpler builds, no build-essential dependency on Linux |
| Embedded frontend | Single binary distribution, no separate deployment |
| Vite over Create React App | Faster builds, HMR, active maintenance |
| SOAP XML string replacement | Go's `encoding/xml` cannot produce MS-MDE2 required namespace prefixes; cleanest workaround |
| AES-256-GCM for CA key | Authenticated encryption, nonce+tag format simplifies storage |

## Milestones

| Milestone | Status | Notes |
|-----------|--------|-------|
| M1: Core protocol | 🟡 In Progress | MS-MDE2, XCEP, WSTEP implemented |
| M2: Dashboard | 🟡 In Progress | Basic UI, needs feature parity |
| M3: Policy management | 🔴 Not Started | DDF import, profile creation |
| M4: Production ready | 🔴 Not Started | Security audit, testing |
| M5: Release | 🔴 Not Started | Documentation, distribution |