from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import re
import secrets
import sqlite3
import tempfile
import time
import urllib.parse
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from collections.abc import Iterable


APP_NAME = "Secure Login"
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("DB_PATH", Path(tempfile.gettempdir()) / "secure_login.sqlite3"))
STATIC_DIR = BASE_DIR / "static"
PASSWORD_ITERATIONS = 310_000
SESSION_TTL_SECONDS = 60 * 60 * 8
LOCKOUT_SECONDS = 10 * 60
MAX_FAILED_LOGINS = 5
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def now() -> int:
    return int(time.time())


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                totp_secret TEXT,
                created_at INTEGER NOT NULL,
                failed_logins INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now(),))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return "pbkdf2_sha256${}${}${}".format(
        PASSWORD_ITERATIONS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iteration_text, salt_text, digest_text = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            base64.urlsafe_b64decode(salt_text.encode("ascii")),
            int(iteration_text),
        )
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def session_hash(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("ascii")).hexdigest()


def make_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, interval: int | None = None) -> str:
    padded = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = (now() if interval is None else interval) // 30
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def verify_totp(secret: str, code: str) -> bool:
    clean = re.sub(r"\s+", "", code)
    if not re.fullmatch(r"\d{6}", clean):
        return False
    current = now()
    for drift in (-30, 0, 30):
        if hmac.compare_digest(totp_code(secret, current + drift), clean):
            return True
    return False


def validate_registration(username: str, email: str, password: str) -> list[str]:
    errors = []
    if not USERNAME_RE.fullmatch(username):
        errors.append("Username must be 3-30 characters using letters, numbers, dot, dash, or underscore.")
    if not EMAIL_RE.fullmatch(email):
        errors.append("Enter a valid email address.")
    if len(password) < 12:
        errors.append("Password must be at least 12 characters.")
    if password.lower() == password or password.upper() == password or not re.search(r"\d", password):
        errors.append("Password must include mixed case letters and at least one number.")
    return errors


def page(title: str, body: str, user: sqlite3.Row | None = None) -> bytes:
    nav = (
        f'<a href="/">Home</a><a href="/dashboard">Dashboard</a>'
        f'<form method="post" action="/logout" class="nav-form">'
        f'<input type="hidden" name="csrf" value="{html.escape(user["csrf_token"]) if user else ""}">'
        f'<button type="submit">Log out</button></form>'
        if user
        else '<a href="/register">Register</a><a href="/login">Log in</a>'
    )
    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)} - {APP_NAME}</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body>
  <header>
    <strong>{APP_NAME}</strong>
    <nav>{nav}</nav>
  </header>
  <main>{body}</main>
</body>
</html>"""
    return document.encode("utf-8")


def alert(messages: list[str] | str, kind: str = "error") -> str:
    if isinstance(messages, str):
        messages = [messages]
    items = "".join(f"<li>{html.escape(message)}</li>" for message in messages)
    return f'<div class="alert {kind}"><ul>{items}</ul></div>'


def field(label: str, name: str, input_type: str = "text", autocomplete: str = "") -> str:
    return (
        f'<label>{html.escape(label)}'
        f'<input name="{html.escape(name)}" type="{html.escape(input_type)}" '
        f'autocomplete="{html.escape(autocomplete)}" required></label>'
    )


class App(BaseHTTPRequestHandler):
    server_version = "SecureLogin/1.0"

    def do_GET(self) -> None:
        self.route("GET")

    def do_POST(self) -> None:
        self.route("POST")

    def route(self, method: str) -> None:
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            if path.startswith("/static/") and method == "GET":
                return self.serve_static(path)
            routes = {
                ("GET", "/"): self.home,
                ("GET", "/register"): self.register_form,
                ("POST", "/register"): self.register,
                ("GET", "/login"): self.login_form,
                ("POST", "/login"): self.login,
                ("GET", "/verify-2fa"): self.two_factor_form,
                ("POST", "/verify-2fa"): self.two_factor_verify,
                ("GET", "/dashboard"): self.dashboard,
                ("GET", "/2fa/setup"): self.setup_2fa_form,
                ("POST", "/2fa/setup"): self.setup_2fa,
                ("POST", "/2fa/disable"): self.disable_2fa,
                ("POST", "/logout"): self.logout,
            }
            handler = routes.get((method, path))
            if handler:
                return handler()
            self.respond(404, page("Not found", "<section><h1>Page not found</h1></section>", self.current_user()))
        except Exception:
            self.respond(500, page("Error", alert("Something went wrong. Check the server console.")))
            raise

    def send_extra_headers(self, headers: dict[str, str | Iterable[str]] | None) -> None:
        for key, value in (headers or {}).items():
            if isinstance(value, str):
                self.send_header(key, value)
            else:
                for item in value:
                    self.send_header(key, item)

    def respond(self, status: int, body: bytes, headers: dict[str, str | Iterable[str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'")
        self.send_extra_headers(headers)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, location: str, headers: dict[str, str | Iterable[str]] | None = None) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_extra_headers(headers)
        self.end_headers()

    def serve_static(self, path: str) -> None:
        target = (STATIC_DIR / Path(path).name).resolve()
        if STATIC_DIR.resolve() not in target.parents or not target.exists():
            self.send_error(404)
            return
        content_type = "text/css" if target.suffix == ".css" else "application/octet-stream"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8")
        return {k: v[0] for k, v in urllib.parse.parse_qs(raw, keep_blank_values=True).items()}

    def cookie_value(self, name: str) -> str | None:
        jar = cookies.SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get(name)
        return morsel.value if morsel else None

    def set_session_cookie(self, session_id: str) -> str:
        cookie = cookies.SimpleCookie()
        cookie["session"] = session_id
        cookie["session"]["httponly"] = True
        cookie["session"]["samesite"] = "Lax"
        cookie["session"]["path"] = "/"
        cookie["session"]["max-age"] = str(SESSION_TTL_SECONDS)
        return cookie.output(header="").strip()

    def clear_session_cookie(self) -> str:
        cookie = cookies.SimpleCookie()
        cookie["session"] = ""
        cookie["session"]["httponly"] = True
        cookie["session"]["samesite"] = "Lax"
        cookie["session"]["path"] = "/"
        cookie["session"]["max-age"] = "0"
        return cookie.output(header="").strip()

    def current_user(self) -> sqlite3.Row | None:
        session_id = self.cookie_value("session")
        if not session_id:
            return None
        with db() as conn:
            row = conn.execute(
                """
                SELECT users.*, sessions.csrf_token
                FROM sessions
                JOIN users ON users.id = sessions.user_id
                WHERE sessions.id_hash = ? AND sessions.expires_at > ?
                """,
                (session_hash(session_id), now()),
            ).fetchone()
        return row

    def require_user(self) -> sqlite3.Row | None:
        user = self.current_user()
        if not user:
            self.redirect("/login")
        return user

    def require_csrf(self, user: sqlite3.Row, form: dict[str, str]) -> bool:
        return hmac.compare_digest(form.get("csrf", ""), user["csrf_token"])

    def create_session(self, user_id: int) -> str:
        session_id = secrets.token_urlsafe(32)
        with db() as conn:
            conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
            conn.execute(
                "INSERT INTO sessions (id_hash, user_id, csrf_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
                (session_hash(session_id), user_id, secrets.token_urlsafe(32), now() + SESSION_TTL_SECONDS, now()),
            )
        return session_id

    def home(self) -> None:
        user = self.current_user()
        body = """<section class="hero">
  <h1>Secure account access, built small and readable.</h1>
  <p>This app demonstrates registration, login, hashed passwords, SQL injection resistance, server-side sessions, logout, and optional 2FA.</p>
  <div class="actions"><a class="button" href="/register">Create account</a><a class="button ghost" href="/login">Log in</a></div>
</section>"""
        self.respond(200, page("Home", body, user))

    def register_form(self, errors: list[str] | None = None) -> None:
        body = f"""<section class="panel">
  <h1>Create account</h1>
  {alert(errors) if errors else ""}
  <form method="post" action="/register">
    {field("Username", "username", "text", "username")}
    {field("Email", "email", "email", "email")}
    {field("Password", "password", "password", "new-password")}
    <button type="submit">Register</button>
  </form>
</section>"""
        self.respond(200, page("Register", body, self.current_user()))

    def register(self) -> None:
        data = self.form()
        username = data.get("username", "").strip()
        email = data.get("email", "").strip()
        password = data.get("password", "")
        errors = validate_registration(username, email, password)
        if errors:
            return self.register_form(errors)
        try:
            with db() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                    (username, email, hash_password(password), now()),
                )
        except sqlite3.IntegrityError:
            return self.register_form(["Username or email is already registered."])
        self.redirect("/login")

    def login_form(self, error: str | None = None) -> None:
        body = f"""<section class="panel">
  <h1>Log in</h1>
  {alert(error) if error else ""}
  <form method="post" action="/login">
    {field("Username or email", "identifier", "text", "username")}
    {field("Password", "password", "password", "current-password")}
    <button type="submit">Log in</button>
  </form>
</section>"""
        self.respond(200, page("Login", body, self.current_user()))

    def login(self) -> None:
        data = self.form()
        identifier = data.get("identifier", "").strip()
        password = data.get("password", "")
        with db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ? COLLATE NOCASE",
                (identifier, identifier),
            ).fetchone()
            generic_error = "Invalid credentials, or the account is temporarily locked."
            if not user or (user["locked_until"] and user["locked_until"] > now()):
                return self.login_form(generic_error)
            if not verify_password(password, user["password_hash"]):
                failed = user["failed_logins"] + 1
                locked_until = now() + LOCKOUT_SECONDS if failed >= MAX_FAILED_LOGINS else None
                conn.execute(
                    "UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?",
                    (failed, locked_until, user["id"]),
                )
                return self.login_form(generic_error)
            conn.execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user["id"],))
            if user["totp_secret"]:
                temp = secrets.token_urlsafe(24)
                self.server.pending_2fa[temp] = {"user_id": user["id"], "expires_at": now() + 300}
                self.redirect("/verify-2fa", {"Set-Cookie": f"pending_2fa={temp}; HttpOnly; SameSite=Lax; Path=/; Max-Age=300"})
                return
        session_id = self.create_session(user["id"])
        self.redirect("/dashboard", {"Set-Cookie": self.set_session_cookie(session_id)})

    def two_factor_form(self, error: str | None = None) -> None:
        if not self.cookie_value("pending_2fa"):
            return self.redirect("/login")
        body = f"""<section class="panel">
  <h1>Two-factor code</h1>
  {alert(error) if error else ""}
  <form method="post" action="/verify-2fa">
    {field("Authenticator code", "code", "text", "one-time-code")}
    <button type="submit">Verify</button>
  </form>
</section>"""
        self.respond(200, page("2FA", body))

    def two_factor_verify(self) -> None:
        token = self.cookie_value("pending_2fa")
        pending = self.server.pending_2fa.get(token or "")
        if not pending or pending["expires_at"] < now():
            return self.login_form("Two-factor verification expired. Log in again.")
        data = self.form()
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE id = ?", (pending["user_id"],)).fetchone()
        if not user or not verify_totp(user["totp_secret"], data.get("code", "")):
            return self.two_factor_form("Invalid two-factor code.")
        self.server.pending_2fa.pop(token, None)
        session_id = self.create_session(user["id"])
        headers = {
            "Set-Cookie": [
                self.set_session_cookie(session_id),
                "pending_2fa=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
            ]
        }
        self.redirect("/dashboard", headers)

    def dashboard(self) -> None:
        user = self.require_user()
        if not user:
            return
        status = "Enabled" if user["totp_secret"] else "Not enabled"
        body = f"""<section class="panel wide">
  <h1>Dashboard</h1>
  <p>Signed in as <strong>{html.escape(user["username"])}</strong>.</p>
  <dl><dt>Email</dt><dd>{html.escape(user["email"])}</dd><dt>Two-factor authentication</dt><dd>{status}</dd></dl>
  <div class="actions"><a class="button" href="/2fa/setup">Manage 2FA</a></div>
</section>"""
        self.respond(200, page("Dashboard", body, user))

    def setup_2fa_form(self, error: str | None = None, secret: str | None = None) -> None:
        user = self.require_user()
        if not user:
            return
        secret = secret or make_totp_secret()
        issuer = urllib.parse.quote(APP_NAME)
        account = urllib.parse.quote(user["email"])
        uri = f"otpauth://totp/{issuer}:{account}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
        enabled = bool(user["totp_secret"])
        body = f"""<section class="panel wide">
  <h1>Two-factor authentication</h1>
  {alert(error) if error else ""}
  <p>Status: <strong>{"Enabled" if enabled else "Not enabled"}</strong></p>
  <form method="post" action="/2fa/setup">
    <input type="hidden" name="csrf" value="{html.escape(user["csrf_token"])}">
    <input type="hidden" name="secret" value="{html.escape(secret)}">
    <label>Secret key<input readonly value="{html.escape(secret)}"></label>
    <label>Authenticator URI<textarea readonly>{html.escape(uri)}</textarea></label>
    {field("Current password", "password", "password", "current-password")}
    {field("6-digit code", "code", "text", "one-time-code")}
    <button type="submit">Enable 2FA</button>
  </form>
  {f'<form method="post" action="/2fa/disable" class="danger"><input type="hidden" name="csrf" value="{html.escape(user["csrf_token"])}"><button type="submit">Disable 2FA</button></form>' if enabled else ""}
</section>"""
        self.respond(200, page("Manage 2FA", body, user))

    def setup_2fa(self) -> None:
        user = self.require_user()
        if not user:
            return
        data = self.form()
        if not self.require_csrf(user, data):
            return self.respond(403, page("Forbidden", alert("Invalid security token."), user))
        secret = data.get("secret", "")
        if not verify_password(data.get("password", ""), user["password_hash"]):
            return self.setup_2fa_form("Current password is incorrect.", secret)
        if not verify_totp(secret, data.get("code", "")):
            return self.setup_2fa_form("Authenticator code did not match.", secret)
        with db() as conn:
            conn.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
        self.redirect("/dashboard")

    def disable_2fa(self) -> None:
        user = self.require_user()
        if not user:
            return
        data = self.form()
        if not self.require_csrf(user, data):
            return self.respond(403, page("Forbidden", alert("Invalid security token."), user))
        with db() as conn:
            conn.execute("UPDATE users SET totp_secret = NULL WHERE id = ?", (user["id"],))
        self.redirect("/dashboard")

    def logout(self) -> None:
        user = self.current_user()
        data = self.form()
        if user and self.require_csrf(user, data):
            session_id = self.cookie_value("session")
            with db() as conn:
                conn.execute("DELETE FROM sessions WHERE id_hash = ?", (session_hash(session_id or ""),))
        self.redirect("/", {"Set-Cookie": self.clear_session_cookie()})

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")


class SecureLoginServer(ThreadingHTTPServer):
    pending_2fa: dict[str, dict[str, int]]

    def __init__(self, server_address: tuple[str, int], handler: type[BaseHTTPRequestHandler]):
        super().__init__(server_address, handler)
        self.pending_2fa = {}


if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print(f"{APP_NAME} running at http://{host}:{port}")
    SecureLoginServer((host, port), App).serve_forever()
