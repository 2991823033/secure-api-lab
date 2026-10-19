# Secure REST API — Work 1

HDU Information Security Laboratory Work 1: **Secure REST API Development with
CI/CD and Real CVE Vulnerability Analysis**.

This repository contains a small Flask + SQLite API that demonstrates the full
security lifecycle described in the lab manual:

1. A functional API protected against the OWASP Top 10 (SQLi, XSS, broken auth).
2. A GitHub Actions CI/CD pipeline that runs SAST (Bandit) and SCA
   (OWASP Dependency-Check) on every push.
3. Reproduction, root-cause analysis, and remediation of a real CVE
   (`CVE-2013-4547`) in a controlled Docker/Vulhub environment.

---

## 1. Project & API description

| Method | Endpoint           | Auth        | Description                                  |
|--------|--------------------|-------------|----------------------------------------------|
| POST   | `/auth/register`   | none        | Create a new account (password hashed)       |
| POST   | `/auth/login`      | none        | Authenticate and return a JWT                |
| GET    | `/api/data`        | **JWT required** | Return the list of posts (user data escaped) |

### How to run

```bash
python -m venv venv
venv\Scripts\activate          # Windows  (or: source venv/bin/activate)
pip install -r requirements.txt
python db.py                   # create SQLite schema + seed data
python app.py                  # start the server on http://localhost:5000
```

### How to call

```bash
# 1. Register a user
curl -X POST http://localhost:5000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"S3cure!Pass"}' 

# 2. Login -> get a JWT
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"login":"admin","password":"admin123"}'
# -> {"token":"eyJhbGciOiJIUzI1NiIs..."}

# 3. Access protected data WITH the token
curl http://localhost:5000/api/data \
  -H "Authorization: Bearer <TOKEN>"

# 4. Access protected data WITHOUT the token -> 401
curl http://localhost:5000/api/data
# -> {"error":"missing token"}
```

---

## 2. Implemented security measures

### 2.1 SQL injection (SQLi) — parameterized queries

Every SQL statement uses **parameterized queries** (the `?` placeholder) so user
input is never concatenated into the SQL string.

```python
user = db.execute(
    "SELECT * FROM users WHERE username = ?", (username,)
).fetchone()
```

Because the value is bound as a parameter, an input such as
`admin" OR 1=1 --` is treated as a literal string, not as SQL.

### 2.2 Cross-site scripting (XSS) — output escaping

All user-supplied values returned to the client are passed through
`escape()` before being serialised into the JSON response.

```python
result = [{"title": escape(p["title"]),
           "content": escape(p["content"]),
           "author": escape(p["author"])} for p in posts]
```

This neutralises HTML/JavaScript (e.g. `<script>alert(1)</script>`) embedded in
stored data.

### 2.3 Broken authentication — JWT + password hashing

- **JWT**: on successful login the server issues a signed JWT; a `require_auth`
  decorator verifies the token on every protected endpoint.
- **Password hashing**: passwords are stored using **scrypt** (one of the
  algorithms required by the lab manual — bcrypt/scrypt/Argon2), via
  `generate_password_hash` / `check_password_hash` — never in plaintext.

```python
password_hash = generate_password_hash(password, method="scrypt")
```

---

## 3. CI/CD pipeline (SAST + SCA)

Defined in [`.github/workflows/ci.yml`](.github/workflows/ci.yml). On every
push / pull request to `main`:

- **SAST** — [Bandit](https://bandit.readthedocs.io/) scans the Python source
  for common security issues and uploads a JSON report.
- **SCA** — [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
  scans the third-party dependencies for known CVEs and uploads an HTML report.

### Reports

> _Screenshot placeholders — replace with screenshots from the `Actions` tab of
> your repository showing a successful run._

![SAST Bandit report](docs/bandit-report.png)

![SCA Dependency-Check report](docs/dependency-check-report.png)

A link to the last successful pipeline run:

> https://github.com/2991823033/secure-api-lab/actions/runs/39195977843

---

## 4. CVE reproduction & remediation

Selected vulnerability: **CVE-2013-4547** (Nginx filename logic vulnerability).

### 4.1 Summary

Nginx 0.8.41–1.4.3 (and 1.5.x before 1.5.7) incorrectly parses URIs containing
an unescaped space. A request such as `1.gif\x20\x00.php` matches the `\.php$`
location (it ends with `.php`), so Nginx routes it to PHP-FPM — but the NUL
byte truncates the script filename back to `1.gif ` (trailing space). An
attacker uploads a file named `1.gif ` (whose PHP code bypasses the `.php`
blacklist) and then requests it with the space+NUL trick, achieving **remote
code execution**.

### 4.2 Reproduction steps

```bash
cd vulhub/nginx/CVE-2013-4547
docker compose up -d                       # Nginx 1.4.2 + PHP 5.6-FPM
# 1) upload a file "1.gif " (trailing space) containing PHP code
python poc/upload.py
# 2) request it with a raw space + NUL byte in the URI
python poc/exploit.py
# -> "CVE-2013-4547 RCE SUCCESS! uid=33(www-data) ..."
```

> _Paste your reproduction screenshots here._

### 4.3 Root cause analysis

The root cause is a **URI-parsing (input-handling) logic error in Nginx**, not
an application-code bug. Nginx matches the `\.php$` location against the full
URI (so `1.gif\x20\x00.php` matches), but then truncates the script filename at
the NUL byte, handing `1.gif ` to PHP-FPM. The application's `.php` blacklist
is sound in isolation — the web server's filename resolution is what lets the
attacker bypass it.

### 4.4 Applied fix

The fix (see [`cve/index.php`](cve/index.php)) adds strict filename validation
at the application layer (defense-in-depth): any filename outside
`[a-zA-Z0-9._-]` is rejected, which blocks the trailing-space filename. (The
root fix in production is upgrading Nginx to >= 1.4.4 / 1.5.7.)

### 4.5 Verification

After `docker compose restart` (to clear PHP-FPM opcache), the same upload is
rejected with `Invalid filename.`, and the exploitation request returns
`No input file specified.` — the attack no longer succeeds, while legitimate
uploads still work.

---

## 5. Repository structure

```
.
├── app.py                      # Flask application (3 endpoints)
├── db.py                       # SQLite schema + seed data
├── requirements.txt            # Python dependencies
├── .github/workflows/ci.yml    # CI/CD (SAST + SCA)
├── cve/
│   ├── index.php               # fixed file for CVE-2013-4547
│   └── CVE-2013-4547.md        # CVE analysis report
├── poc/
│   ├── upload.py               # upload "1.gif " (trailing-space) payload
│   └── exploit.py              # send raw space + NUL byte URI -> RCE
└── README.md
```

## 6. Control questions (brief answers)

1. **bcrypt/scrypt vs SHA-256** — bcrypt/scrypt are slow, salted key-derivation
   functions with an adjustable cost factor, designed for password hashing;
   SHA-256 is fast, unsalted by itself, and vulnerable to brute-force and
   rainbow-table attacks.
2. **SAST vs DAST** — SAST analyses source code without running it; DAST tests a
   running application from the outside.
3. **JWT mechanism** — header.payload.signature; the server verifies the
   signature with its secret key, and checks `exp`/claims.
4. **Dependency risks** — unpatched third-party libraries can introduce known
   CVEs (supply-chain / SCA issues).
5. **Docker + Vulhub advantages** — reproducible, isolated, disposable
   environments; no risk to the host.
6. **Vulnerability vs exploit** — a vulnerability is a weakness; an exploit is
   code that takes advantage of it. We reproduced an exploit against a known
   CVE.
7. **Regression testing** — a patch must not break legitimate functionality.
8. **Why CVEs matter to a security specialist** — they map known weaknesses to
   real attacker techniques (see MITRE ATT&CK / NVD).
