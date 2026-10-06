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

## Important production limitation
The original application uses SQLite and keeps Telethon clients in process memory. Vercel serverless functions are ephemeral, so SQLite on the local filesystem is **not durable storage**, and long-lived Telethon/SSE connections cannot be relied on across invocations.

For a reliable public deployment, keep the Vercel web/API layer but move the database to a hosted PostgreSQL/SQLite-compatible service and run long-lived Telegram workers on a worker host. The current package is suitable for Vercel testing/development, but do not use local SQLite as the only production database on Vercel.

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
