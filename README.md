# TaskFlow Invest

TaskFlow Invest is a crypto-focused task investing app with a browser UI in `index.html` and a Node.js API in `server.js`.

## What Is Included

- JWT authentication with password hashing and HttpOnly session cookies.
- SQLite persistence through Node's built-in `node:sqlite` module.
- Per-user task ownership.
- Task search, filters, status, editing, deletion, dashboard stats, and Pro CSV export.
- Investment tiers: `silver` (10%), `gold` (30%), `diamond` (50%), with enforced investment ranges.
- Invest page for browsing opportunities by tier/currency.
- Starter/Pro plan gating with a configurable task limit.
- Stripe Checkout, Stripe Billing Portal, and Stripe webhook handling.
- Polished sign-in and registration flow with inline validation and toast notifications.
- API rate limiting and baseline HTTP hardening with Helmet.
- Environment-based configuration through `.env`.

## Current Brand Direction

- Product name: TaskFlow Invest
- Positioning: crypto investment task flow with tiered ROI and platform fee tracking
- Theme: Light + Dark (saved in `taskflowSettings`)
- Primary color (light): `#0ea5a4`
- Tone: fintech, direct, bilingual-ready

## Local Development

Use Node.js 24 or newer.

Install dependencies:

```bash
npm install
```

Create your environment file:

```bash
cp .env.example .env
```

Set a long random `JWT_SECRET`, then run:

```bash
npm start
```

Open `http://localhost:3000`.

## Live App

Production URL:

```text
https://taskflow-pro-iraq.fly.dev/
```

## API

- `POST /api/register` creates a user and returns `{ user, token }`.
- `POST /api/login` returns `{ user, token }`.
- `POST /api/logout` clears the session cookie.
- `GET /api/me` returns the current user.
- `PUT /api/me` updates the current user.
- `GET /api/tasks` lists tasks for the signed-in user.
- `POST /api/tasks` creates a task.
- `PUT /api/tasks/:id` updates a task owned by the signed-in user.
- `DELETE /api/tasks/:id` deletes a task owned by the signed-in user.
- `GET /api/export/tasks.csv` exports tasks as CSV for Pro accounts.
- `GET /api/billing/status` returns plan and usage status.
- `POST /api/billing/create-checkout-session` creates a Stripe Checkout session.
- `POST /api/billing/portal` opens Stripe Billing Portal.
- `POST /api/billing/webhook` receives Stripe events.
- `POST /api/me/backfill-starter-tasks` inserts missing starter tasks (no duplicates).
- `POST /api/me/backfill-investments` backfills missing investment fields for older tasks.
- `GET /api/health` reports API health.

Authenticated endpoints accept the HttpOnly session cookie. API clients can also send:

```text
Authorization: Bearer <token>
```

## Production Hosting

This project now needs a Node-capable host because the app depends on `/api/*`.

Good options:

- Render
- Railway
- Fly.io
- A VPS with Node.js and a reverse proxy

Netlify static hosting alone is no longer enough for the full product. You can still host the frontend there, but the API must run on a backend host and the frontend API URLs would need to point to that backend.

## Deploy To Fly.io (SQLite + Volume)

This project uses SQLite, so it needs a Fly Volume for persistence.

1. Install `flyctl` and sign in:
   `fly auth login`
2. Create the Fly app without deploying:
   `fly launch --no-deploy`
3. Copy `fly.toml.example` to `fly.toml` and update:
   - `app` name (must match the one you created)
   - `primary_region` (choose a region close to you)
4. Create a volume in the same region:
   `fly volumes create taskflow_data --size 1 --region <region>`
5. Set secrets:
   `fly secrets set NODE_ENV=production DB_FILE=/data/taskflow.db JWT_SECRET=<long-random> CORS_ORIGIN=https://<app>.fly.dev APP_URL=https://<app>.fly.dev STARTER_TASK_LIMIT=25`
6. Deploy:
   `fly deploy`

Current app commands:

```bash
npm run fly:status
npm run fly:logs
npm run fly:deploy
```

## Stripe Setup

This project already includes the API routes needed for Stripe Billing:

- `POST /api/billing/create-checkout-session`
- `POST /api/billing/portal`
- `POST /api/billing/webhook`

To enable it in production:

1. Create a Stripe Product + recurring Prices for Pro (monthly + yearly).
2. Set Stripe secrets in Fly:
   `fly secrets set STRIPE_SECRET_KEY=sk_live_... STRIPE_PRICE_PRO_MONTHLY=price_month_... STRIPE_PRICE_PRO_YEARLY=price_year_...`
3. Create a Stripe webhook endpoint pointing to:
   `https://taskflow-pro-iraq.fly.dev/api/billing/webhook`
4. Subscribe the webhook to:
   `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`
5. Set the webhook secret in Fly:
   `fly secrets set STRIPE_WEBHOOK_SECRET=whsec_...`

Notes:

- `APP_URL` should be set to your final public URL so Stripe redirects land on the right domain.
- Stripe keys are optional in local development. The app runs without billing enabled.

## Required Environment

Use `.env.example` as the template:

- `NODE_ENV=production`
- `PORT=3000`
- `JWT_SECRET=<long random secret>`
- `JWT_EXPIRES_IN=7d`
- `CORS_ORIGIN=https://your-domain.com`
- `DB_FILE=./data/taskflow.db`
- `APP_URL=https://your-domain.com`
- `STRIPE_SECRET_KEY=sk_live_...`
- `STRIPE_WEBHOOK_SECRET=whsec_...`
- `STRIPE_PRICE_PRO=price_...`
- `ADMIN_EMAILS=admin@example.com,admin2@example.com`
- `STARTER_TASK_LIMIT=25`

## Launch Checklist

- Set a real `JWT_SECRET`.
- Use HTTPS.
- Set `CORS_ORIGIN` to the final domain.
- Configure Stripe live keys and webhook.
- Replace placeholder support email and Telegram links.
- Confirm volume snapshots in Fly.
- Test register, login, create task, export, upgrade, and billing portal.
