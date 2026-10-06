# Vercel deployment

This package includes a Vercel entrypoint (`api/index.py`) and `vercel.json`.

## Deploy
1. Extract the project and push the `webapp` folder to a GitHub repository.
2. Import the repository into Vercel.
3. Set these environment variables in Vercel:
   - `SECRET_KEY` = a long random value
   - `ADMIN_USERNAME` = your admin username
   - `ADMIN_PASSWORD` = your admin password
4. Deploy.

## Database
Storage runs on MongoDB Atlas (`db.py`), not local SQLite — Vercel's filesystem is read-only outside `/tmp`, so a local `.sqlite` file never persists there (that's the original `unable to open database file` crash). The Atlas connection string is hardcoded directly in `db.py`.

One thing to check in Atlas before deploying: under **Network Access**, add `0.0.0.0/0` (allow from anywhere) — Vercel's serverless functions don't have a fixed IP, so Atlas has to accept connections from any address, or every request will fail to connect.

Integer-style ids (matching the `<int:...>` routes and templates) are preserved via an auto-increment counter collection, so nothing else in the app had to change — same function names and return shapes as before.

## Still a limitation
Vercel serverless functions are ephemeral, so long-lived Telethon/SSE connections (e.g. the live "give message" stream) cannot be relied on across invocations. For that piece specifically, consider running a small always-on worker host alongside the Vercel web/API layer.

## API
Dashboard -> **API Docs**.

Endpoints:
- `GET /api/v1/me`
- `GET /api/v1/sessions`
- `GET /api/v1/sessions/<id>/2fa`
- `POST /api/v1/sessions/<id>/2fa/reset`

Authentication:
`Authorization: Bearer YOUR_API_KEY`

The 2FA reset endpoint starts Telegram's official password-reset flow. It does not delete or reset the Telegram account. Telegram may require recovery-email confirmation or a waiting period.
