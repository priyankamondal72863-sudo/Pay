# Zyvo Gateway — Part 1
## Render deploy
1. Push to GitHub → Render "New Web Service" (or Blueprint using render.yaml). Build: `pip install -r requirements.txt`, Start: `gunicorn app:app -c gunicorn.conf.py` (or `uvicorn main:app --host 0.0.0.0 --port $PORT` — both work)
2. Env vars: SECRET_KEY (random, never change later or saved credentials become unreadable), ADMIN_EMAIL, ADMIN_PASSWORD (creates Owner on first boot), DATABASE_URL (Render Postgres internal URL).
3. Without DATABASE_URL it uses SQLite — Render free disk is wiped on every redeploy/sleep, so use Postgres.
4. Login as owner → /admin. Merchants: register → Gateways (Paytm staging creds) → Test → Enable → API Keys.
Free Render sleeps after 15 min idle; first request is slow.

## Part 2 additions
Optional env vars: SMTP_HOST, SMTP_PORT (587), SMTP_USER, SMTP_PASS, SMTP_FROM (email alerts + password reset); TELEGRAM_BOT_TOKEN (Telegram alerts; users add their chat ID in Settings).
Background worker (webhook retries, pending-payment reconciliation, refund status, subscription expiry) runs inside the web process. On Render free it only runs while the service is awake.
Plans (Free/Basic/Pro/Business/Lifetime) are seeded on first boot; edit them in Owner Panel → Plans.
Not yet done: maintenance mode, support tickets, IP whitelist, enforcing the plan's API-request limit, automatic collection of subscription payments (owner activates plans manually).

## Keep-alive
The service pings its own /healthz every 5 min (uses RENDER_EXTERNAL_URL, set by Render automatically) so the free instance does not go to sleep.
