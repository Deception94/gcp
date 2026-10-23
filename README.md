# Secure Finance Portal — Web Application Security Lab

An educational finance-tracker web app built to demonstrate practical web application security controls using Flask and SQLite.

## Security controls demonstrated
- Password hashing and verification
- Session renewal after login
- CSRF tokens for state-changing POST requests
- Parameterized SQL queries
- Server-side validation of amounts and descriptions
- Per-user transaction isolation and ownership checks
- HTML output escaping through Jinja templates
- Security response headers and minimal audit logging
- Automated security regression tests

## Run locally
Python 3.10+ required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

Local classroom demo accounts:
- alice@example.com / AliceDemo!23
- bob@example.com / BobDemoPass!23

These are intentionally public demo credentials. Never reuse them or expose this demo to the internet.

## Run tests
```bash
python -m unittest -v
```

## Suggested demo
1. Sign in as Alice and add a transaction.
2. Sign out and sign in as Bob; Alice's transaction should not be visible.
3. Try a negative amount; server-side validation should reject it.
4. Run the tests to demonstrate password verification, CSRF enforcement, user isolation, POST-only logout, and security headers.

## Architecture
Browser → Flask routes and validation → SQLite database. Transactions are associated with an authenticated user ID, and ownership is checked server-side for reads and mutations.

## Limitations
This is a teaching prototype, not a production financial service. It does not include MFA, rate limiting, password reset, production secrets management, TLS termination, or formal penetration testing. Before deployment, configure HTTPS, a strong environment-based secret, secure cookie settings, rate limiting, monitoring, backups, and a reviewed production configuration. Do not use real financial data.

Student: Tanmay Mahajan — EXTC-B — Roll No. 23104B0021

Educational use only. Test only this application or systems for which you have permission.