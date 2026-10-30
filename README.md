# Student Connect

A responsive student registration web application and protected admin dashboard for an initial selection task.

## Features

- Student registration with name, Indian mobile number, email, predefined college and study year.
- Server-side validation and duplicate mobile/email protection.
- SQLite persistence.
- Admin login with bcrypt password hashing, HttpOnly/SameSite cookie and expiring server-side sessions.
- Dashboard totals, college/year distribution, search, filters, pagination and filtered CSV export.
- Mobile and email verification status tracking. Statuses remain **Pending** until real verification providers are integrated.
- Rate limiting on registration and login endpoints, Helmet security headers and parameterized SQL queries.
- A CSV file with 60 synthetic test records and a manual test checklist.

## Requirements

- Node.js 20+ recommended
- npm

## Run locally

1. Extract the ZIP and open a terminal in the `student-connect` folder.
2. Install dependencies:

   ```bash
   npm install
   ```

3. Copy `.env.example` to `.env` and change `SESSION_SECRET`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD` to unique values. Do not commit `.env`.
4. Start the application:

   ```bash
   npm start
   ```

5. Open `http://localhost:3000`.
6. Open **Admin portal** to sign in using the credentials you configured in `.env`.

On first startup, the database is created at `data/student-connect.db`. The initial admin is created from the environment values only if that username does not already exist. If changing the password after the first startup, update the admin password through a secure password-management feature or reset the local test database.

## Import 60 synthetic records

The provided `students.csv` is a test fixture. It contains 60 synthetic records; it is not a list of real people and does not represent real verification. To import into a fresh database for demo/testing, run:

```bash
node scripts/import-test-data.js
```

This script imports the included synthetic CSV into the local SQLite database. Use it only in a test/demo database; it does not delete existing records and will skip duplicate mobile/email values.

## Test

```bash
npm test
```

The automated tests cover validation rules and CSV fixture integrity. Also follow `tests/manual-test-checklist.md` to check the full browser workflow.

## Important limitations before production

- SMS OTP and email confirmation are not integrated. Verification remains Pending until a real provider and verification workflow are implemented.
- The predefined colleges are sample options; replace them with the organization's official list if provided.
- This is a local assessment starter. Before deployment, use HTTPS, a strong secret and unique admin password, backup and retention policies, appropriate privacy notice/consent, and review security settings.
- Admin accounts are initialized from environment values on first startup; there is no in-app admin creation or password reset UI.
- This demo's browser UI is served by Express. Keep the backend running; opening `index.html` directly will not connect to the API.

## Submission

Suggested repository files:
- Application source (`server.js`, `public/`)
- `students.csv` (60 synthetic test records)
- `README.md`
- `tests/manual-test-checklist.md`

Do not include `.env`, database files, or `node_modules` in the repository/ZIP.
