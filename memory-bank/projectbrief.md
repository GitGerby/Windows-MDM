# Project Brief: Latchz MDM

> **Status:** Proof of Concept / Work in Progress — NOT production-ready
> **Module:** `github.com/latchzmdm/latchz`

## Overview

Latchz is an open-source, single-binary Windows MDM (Mobile Device Management) server written in Go with a React dashboard. It enables zero-touch enrollment and continuous configuration management of Windows 10/11 devices via the native OMA-DM protocol.

## Core Goals

1. **Native Windows Protocol Support** — Full MS-MDE2 enrollment and OMA-DM/SyncML policy management without requiring a custom agent on managed devices.
2. **Single Binary Distribution** — The entire server (Go backend + embedded React frontend) compiles into one executable.
3. **Zero-Touch Enrollment** — Windows devices enroll automatically using standard Microsoft enrollment flows (e.g., `enterpriseenrollment.yourdomain.com`).
4. **Auto-TLS** — Native Let's Encrypt integration for painless production deployments.
5. **Modern Dashboard** — Embedded React SPA with glassmorphism styling for device management.

## Key Requirements

- A server with port 443 (and 80 for Auto-TLS) exposed.
- A domain name (`mdm.example.com`).
- An Identity Provider (IdP) via OIDC (Google Workspace, Entra ID, etc.) for dashboard authentication.
- Microsoft DDF (Device Description Framework) schemas imported into the database for the policy catalog.

## Scope

### In Scope
- Windows 10/11 MDM enrollment via OMA-DM
- Policy catalog and configuration profile management
- Device lifecycle operations (lock, wipe, sync, unenroll)
- Device groups and profile assignment
- Compliance tracking
- REST API for dashboard backend
- Auto-enrollment via DNS CNAME discovery

### Out of Scope (Future)
- Mobile device support (iOS/Android)
- Custom agent deployment
- Advanced reporting and analytics
- Multi-tenant isolation

## Dependencies

- **Backend:** Go 1.26+, Chi router, Viper config, go-oidc, golang-migrate
- **Database:** SQLite (dev) or PostgreSQL (production)
- **Frontend:** React 19, TypeScript, Vite, Recharts, React Router
- **TLS:** crypto/tls, ACME (Let's Encrypt)