# Back-end

Laravel 12 REST API and dashboard backend for Bingo, MySQL-backed and PHP-FPM served.

## What it does

This service is the central record-keeping and control plane for the Bingo platform. It exposes a token- and session-authenticated REST API that:

- Receives **reports**, **vulnerabilities**, and **incidents** pushed by the Offensive and Defensive agents.
- Tracks agent **heartbeats** and flags agents that go silent.
- Backs the operator dashboard (`Front-end/`): authentication, stats, search, notifications, and activity logs.
- Exports reports to PDF (`barryvdh/laravel-dompdf`).

Agents authenticate with custom `bingo_ak_` access tokens; dashboard users authenticate via Laravel Sanctum. See the [root README](../README.md) for full-stack setup and the wider system overview.

## How agents connect

Agent endpoints live under `/api/agent/*` and are guarded by the `agent.auth` middleware (`AuthenticateAgent`). A request must carry `Authorization: Bearer bingo_ak_...`. Tokens are minted per user from the dashboard, stored only as SHA-256 hashes (`token_hash`), and limited to 7/14/30-day lifetimes (max 30). `last_used_at` is stamped on every successful call.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/agent/heartbeat` | Upsert agent liveness (`offensive`/`defensive`, status, metadata) |
| `POST` | `/api/agent/reports` | Submit a scan report with nested vulnerabilities |
| `POST` | `/api/agent/incidents` | Submit a WAF/SIEM security incident |

Critical vulnerabilities and high/critical incidents auto-generate dashboard notifications. Dashboard CRUD, auth, search, and token management endpoints live under `/api/*` behind `auth:sanctum` — see `routes/api.php` for the full list.

## Layout

| Path | Responsibility |
| --- | --- |
| `routes/api.php` | All API routes (public auth, Sanctum-protected dashboard, `agent.auth` ingest) |
| `routes/console.php` | Scheduled tasks (token cleanup/warnings, agent status checks) |
| `app/Http/Controllers/` | `Agent`, `Report`, `Vulnerability`, `Incident`, `Auth`, `Dashboard`, `Notification`, `Search`, `ActivityLog`, `AccessToken` controllers |
| `app/Http/Middleware/` | `AuthenticateAgent` (bearer-token agent auth), `CustomCors` |
| `app/Http/Requests/` | Form-request validators for reports, incidents, vulnerabilities, auth, tokens |
| `app/Services/` | Business logic — `AccessTokenService` (token mint/hash/resolve), `Report`, `Vulnerability`, `Incident`, `Auth`, `Dashboard`, `Notification`, `Search` |
| `app/Models/` | `User`, `AccessToken`, `Report`, `Vulnerability`, `Incident`, `IncidentNote`, `Notification`, `AgentHeartbeat`, `ActivityLog` |
| `app/Console/Commands/` | `agents:check-status`, `tokens:cleanup`, `tokens:warn-expiring` |
| `app/Helpers/ActivityLogger.php` | Audit-trail helper used across services |
| `database/migrations/` | Schema for all tables above |
| `database/seeders/` | `AdminSeeder` (default admin), `TestDataSeeder` |
| `config/` | Laravel configuration |
| `Dockerfile` | `php:8.2-fpm` image; Composer install, OPcache config, `config/route/view` cache |
| `docker/php.ini` | OPcache tuning mounted into the PHP-FPM container |
| `nginx/default.conf` | nginx → PHP-FPM (`app:9000`) FastCGI config, 10M upload cap |
| `swagger.json` | OpenAPI description of the API |

## Scheduled tasks

Defined in `routes/console.php`, run by the Laravel scheduler:

- `tokens:cleanup` — daily at 03:00, removes expired access tokens.
- `tokens:warn-expiring` — hourly, notifies on tokens nearing expiry.
- `agents:check-status` — every minute, marks agents offline after 5+ minutes without a heartbeat and notifies.

## Running

This service is intended to run as the `app` (PHP-FPM) container behind the `webserver` (nginx) container; see the root [`docker-compose.yml`](../docker-compose.yml) and root README for the full stack. The API serves on `localhost:8000`, the dashboard on `localhost:5500`.

Local Laravel commands (from this folder, with PHP 8.2 + Composer):

```bash
composer install
cp .env.example .env
php artisan key:generate
php artisan migrate --seed
php artisan serve          # or use the bundled `composer dev`
php artisan schedule:work  # run scheduled tasks locally
```

### Key configuration (`.env`)

- `DB_CONNECTION=mysql`, `DB_HOST`, `DB_DATABASE`, `DB_USERNAME`, `DB_PASSWORD` — MySQL connection (defaults target the compose `db` service / `bingo_db`).
- `APP_KEY` / `APP_URL` — application key and base URL.
- `FRONTEND_URL` and `SANCTUM_STATEFUL_DOMAINS` — dashboard origin and Sanctum stateful domains for cookie auth.
- `MAIL_*` — outbound mail for password reset and notification emails.

See `.env.example` for the full set.
