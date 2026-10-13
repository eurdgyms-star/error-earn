# Error Earn — Full-stack starter

This project extends the uploaded Error Earn demo into a Node.js/Express + SQLite starter with:
- User registration/login using bcrypt password hashing
- Session cookies (`HttpOnly`, `SameSite=Strict`; `Secure` in production)
- CSRF token checks on state-changing API requests
- Rate-limited login/register endpoints
- User task completion with a database uniqueness constraint to prevent repeated rewards
- Wallet balance and withdrawal request records
- Protected admin dashboard for users, tasks, withdrawal decisions and activity logs

## Important scope / payment disclaimer
**bKash and Nagad are not integrated.** The withdrawal flow only records requests and admin decisions; it does not transfer money. Demo task rewards are not real earnings. Before real-money launch, integrate an authorized payment provider through its official merchant API, use server-side verification and idempotency, review Bangladesh legal/tax/consumer-protection requirements, and obtain a security review.

## Requirements
- Node.js 20+
- npm

## Run locally
1. Extract this ZIP.
2. Copy `.env.example` to `.env`.
3. Set a long random `SESSION_SECRET` and a unique strong `ADMIN_PASSWORD`.
4. In a terminal, run:
   ```sh
   npm install
   npm start
   ```
5. Open `http://localhost:3000` for the user panel.
6. Open `http://localhost:3000/admin.html` for the admin panel.
7. Sign in with `ADMIN_USERNAME` and `ADMIN_PASSWORD` from `.env`.

The SQLite database is created automatically at `data/error-earn.sqlite`.

## Production checklist
- Set `NODE_ENV=production`, a strong unique `SESSION_SECRET`, and a unique `ADMIN_PASSWORD` in the hosting environment; do not commit `.env`.
- Serve only behind HTTPS.
- Replace Express's default in-memory session store with a supported persistent store (for example Redis or a database-backed session store) before production.
- Configure backups, database migrations, logging/monitoring, account recovery, email verification, and admin MFA.
- Add a proper payment-provider integration only after merchant onboarding and security review.
- Review retention/privacy rules for payment account numbers. This starter stores the supplied account string for demo review and is not suitable for sensitive real payment data as-is.

## API outline
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/me`
- `GET /api/tasks`
- `POST /api/tasks/:id/complete`
- `GET /api/wallet`
- `POST /api/withdrawals`
- `POST /api/admin/login`
- `GET /api/admin/overview`
- `GET /api/admin/users`
- `PATCH /api/admin/users/:id/status`
- `GET /api/admin/tasks`
- `POST /api/admin/tasks`
- `PATCH /api/admin/tasks/:id/status`
- `DELETE /api/admin/tasks/:id`
- `GET /api/admin/withdrawals`
- `PATCH /api/admin/withdrawals/:id`
- `GET /api/admin/logs`

This is a practical starter scaffold, not a production security certification. Have the code reviewed before handling real users or money.
