# Product Context: Latchz MDM

## Why This Project Exists

Managing Windows devices in an enterprise requires MDM capability, but traditional solutions demand heavy infrastructure, licensing costs, or cloud dependencies. Latchz fills this gap by providing a lightweight, self-hosted MDM server that runs from a single binary with no external dependencies beyond a database.

## Problems It Solves

1. **Zero-Touch Device Provisioning** — IT departments can deploy Windows devices that automatically enroll in MDM upon first boot, without manual configuration steps.
2. **Native Protocol Support** — Windows 10/11 devices use built-in OMA-DM protocols, eliminating the need for custom agent software.
3. **Simplified TLS Management** — Auto-TLS with Let's Encrypt removes certificate management overhead.
4. **Single-Point Deployment** — One binary contains both the API server and the React dashboard, simplifying distribution and updates.

## How It Works

### Enrollment Flow

1. **Discovery** — Windows device looks up `enterpriseenrollment.<domain>` via DNS CNAME, pointing to the Latchz server.
2. **MS-MDE2 Protocol** — Device sends a SOAP discovery request to `/EnterpriseEnrollment/Enrollment.svc`. Latchz responds with enrollment endpoints (XCEP for certs, WSTEP for tokens, OMA-DM for policy).
3. **OIDC Authentication** — User authenticates via their IdP (Google Workspace, Entra ID, etc.) through a webview on the device.
4. **Certificate Enrollment** — Device obtains an mTLS client certificate via MS-XCEP (Windows Certificate Enrollment Protocol).
5. **WSTEP Token Exchange** — Device exchanges its certificate for security tokens via MS-WSTEP.
6. **OMA-DM Sync** — Device connects to `/omadm` periodically to receive policies and report status.

### Policy Management

1. **DDF Import** — Microsoft Device Description Framework files are parsed and imported into the `policy_catalog` table, mapping OMA-DM CSP URIs to human-readable configurations.
2. **Profile Creation** — Admins create configuration profiles in the dashboard, selecting policies from the catalog.
3. **Group Assignment** — Profiles are assigned to device groups for bulk management.
4. **Push/Sync** — Policies are pushed to devices on next check-in or via explicit sync commands.

### Device Management

- **Lock** — Remote lock command sent via OMA-DM
- **Wipe** — Factory reset command via OMA-DM
- **Sync** — Force immediate policy check-in
- **Unenroll** — Remove device from management

## User Experience Goals

### Admin Users
- Clean, modern dashboard for managing devices and policies
- Quick visibility into fleet compliance status
- Simple profile creation with policy catalog search
- Device group management for scalable operations

### End Users
- Completely passive enrollment — no interaction needed beyond initial Windows setup
- Automatic policy application without prompts
- Seamless certificate renewal

## Key Design Principles

- **Standards-compliant** — Implements Microsoft's published MDM protocols faithfully
- **Minimal dependencies** — Only a database is required externally
- **Self-contained** — No microservices, no message queues, no separate frontend deployment
- **Developer-friendly** — Hot-reload development with Vite HMR + Go server