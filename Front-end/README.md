# Front-end

Static dashboard for the Bingo platform — plain HTML pages plus a small vanilla-JS layer that talks to the Laravel API.

## What it does

This is the operator-facing UI for Bingo. There is no build step and no framework: each page is a standalone HTML file styled with the Tailwind CDN, and two shared scripts in `js/` provide the API client and reusable UI. The pages let an operator log in, browse pentest reports and their vulnerabilities, triage SIEM incidents, manage API access tokens (the `bingo_ak_` tokens the agents use to report in), and configure their account.

It is a pure client of the Laravel back-end (`Back-end/`). All data — dashboard stats, reports, vulnerabilities, incidents, notifications, search, audit logs — is fetched over REST from the API; nothing is stored server-side in this folder. In production it is served as static files by nginx.

## Pages

| File | Purpose |
| --- | --- |
| `Login.html` | Email/password login; stores the returned bearer token. |
| `ForgotPassword.html` | Requests a password-reset email. |
| `ResetPassword.html` | Sets a new password from a reset token. |
| `Dashboard.html` | Stats overview with Chart.js charts (severity, incidents, scans, assets) and a date-range selector; recent activity. |
| `Report.html` | Tabbed list of pentest reports and SIEM incidents, with status/severity/type filters and search. |
| `ReportDetail.html` | Single report with its vulnerabilities (add/edit/delete, change severity, mark false-positive) and PDF/JSON export. |
| `Settings.html` | Tabbed Account profile + password, Access Tokens (create/regenerate/extend/revoke), and Audit Log. |

## Shared scripts (`js/`)

| File | Responsibility |
| --- | --- |
| `js/api.js` | `API` module — a `fetch` wrapper over the REST API. Attaches the bearer token, JSON/FormData handling, blob downloads, and auto-redirects to `Login.html` on `401`. Exposes grouped methods: `auth`, `tokens`, `reports`, `vulns`, `incidents`, `notifications`, `dashboard`, `search`, `activityLogs`. |
| `js/components.js` | Shared UI: dark-mode toggle, toasts, modals, pagination, sidebar, page header (global search + notifications poll), severity/status badges, and date/HTML helpers. Also `requireAuth()`, used by pages to gate on a stored token. |

## Configuration

- **API base URL** is hard-coded in `js/api.js`:

  ```js
  const BASE = 'http://localhost:8000/api';
  ```

  Edit this constant to point at a different back-end host.

- **Auth state** lives in `localStorage`: `bingo_token` (bearer token) and `bingo_user`. Dark-mode preference is `bingo_dark`. A `401` from any request clears auth and redirects to `Login.html`.

- **External CDNs** are loaded at runtime: `cdn.tailwindcss.com` (all pages) and `cdn.jsdelivr.net/npm/chart.js@4` (Dashboard). The pages require network access to these CDNs to render correctly.

## Serving

`nginx.conf` is the production server config: it serves this directory as the document root, defaults to `Login.html`, falls back unmatched routes to `Login.html`, and sets a 1-day cache on static assets. The container build copies these files into `/usr/share/nginx/html`.

For local development any static file server works — e.g. open `Login.html` directly, or run `python -m http.server` from this folder — as long as the API at `BASE` is reachable and CORS-permitted.

See the [root README](../README.md) for full stack setup (Docker compose, API, default credentials).
