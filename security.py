"""
Security helpers shared by both login surfaces (seller /login and platform
/owner). Kept in one place so the same brute-force protection, CSRF check,
audit trail, and upload validation logic is used everywhere rather than
re-implemented per-route.
"""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from flask import session, request, abort

# ---------------------------------------------------------------- CSRF
#
# NOT used by the JSON API in app.py - kept here for reference/history. CSRF
# defends against a browser automatically attaching ambient credentials (cookies)
# to a request the user didn't intend. The API doesn't use cookies for auth at
# all (see "bearer-token auth" below), so there's no ambient credential for CSRF
# to protect - a malicious page simply has no way to make the browser send an
# Authorization header it doesn't know. If a future version of this app goes
# back to cookie-based sessions, this section is exactly what to wire back up.

def get_csrf_token():
    """Every session gets one long-lived token. Forms embed it as a hidden
    field; JS fetch() calls send it back as the X-CSRFToken header (see the
    meta tag in base.html)."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
    expected = session.get("csrf_token")
    if not expected or not token or not hmac.compare_digest(token, expected):
        abort(400, description="Your session expired or this form was resubmitted from somewhere else. Refresh and try again.")


def init_csrf(app):
    @app.before_request
    def _check_csrf():
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            # Only state-changing, session-authenticated routes need this -
            # nothing here is a public unauthenticated webhook.
            validate_csrf()

    @app.context_processor
    def _inject_csrf():
        return {"csrf_token": get_csrf_token}


# ---------------------------------------------------------------- brute-force lockout

MAX_ATTEMPTS = 6          # per identifier (username/email) ...
IDENT_WINDOW_MIN = 15     # ... within this many minutes
LOCKOUT_MIN = 15          # ... locks that identifier out for this long

MAX_IP_ATTEMPTS = 25      # a looser, wider net against one IP spraying many identifiers
IP_WINDOW_MIN = 15
IP_LOCKOUT_MIN = 15


def _now():
    return datetime.now(timezone.utc)


def _client_ip():
    # Trust X-Forwarded-For only if you've configured a real proxy in front of this
    # (e.g. behind nginx/Cloudflare). Left simple here; swap for ProxyFix if needed.
    # Behind Cloudflare Tunnel the app only listens on 127.0.0.1, so the only thing
    # that can reach it is cloudflared, and CF-Connecting-IP is set by Cloudflare
    # (a visitor can't forge it). Fall back to X-Forwarded-For for other setups.
    cf = request.headers.get("CF-Connecting-IP")
    if cf:
        return cf.strip()
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


def _check_and_bump(conn, scope, identifier, max_attempts, window_min, lockout_min, bump):
    row = conn.execute(
        "SELECT * FROM auth_attempts WHERE scope=? AND identifier=?", (scope, identifier)
    ).fetchone()

    if row and row["locked_until"]:
        locked_until = datetime.fromisoformat(row["locked_until"])
        if _now() < locked_until:
            return False, int((locked_until - _now()).total_seconds())

    if not bump:
        return True, 0

    if row:
        window_start = datetime.fromisoformat(row["window_start"])
        if _now() - window_start > timedelta(minutes=window_min):
            # window expired - start a fresh count
            conn.execute(
                "UPDATE auth_attempts SET attempt_count=1, window_start=?, locked_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE scope=? AND identifier=?",
                (_now().isoformat(), scope, identifier),
            )
            return True, 0
        new_count = row["attempt_count"] + 1
        locked_until = None
        if new_count >= max_attempts:
            locked_until = (_now() + timedelta(minutes=lockout_min)).isoformat()
        conn.execute(
            "UPDATE auth_attempts SET attempt_count=?, locked_until=?, updated_at=CURRENT_TIMESTAMP WHERE scope=? AND identifier=?",
            (new_count, locked_until, scope, identifier),
        )
        if locked_until:
            return False, lockout_min * 60
        return True, 0
    else:
        conn.execute(
            "INSERT INTO auth_attempts (scope, identifier, attempt_count, window_start) VALUES (?, ?, 1, ?)",
            (scope, identifier, _now().isoformat()),
        )
        return True, 0


def is_locked_out(conn, scope, identifier):
    """Read-only check, call before even looking at the password."""
    ok_ident, retry1 = _check_and_bump(conn, scope, f"ident:{identifier.lower()}", MAX_ATTEMPTS, IDENT_WINDOW_MIN, LOCKOUT_MIN, bump=False)
    ok_ip, retry2 = _check_and_bump(conn, scope, f"ip:{_client_ip()}", MAX_IP_ATTEMPTS, IP_WINDOW_MIN, IP_LOCKOUT_MIN, bump=False)
    if not ok_ident:
        return True, retry1
    if not ok_ip:
        return True, retry2
    return False, 0


def record_failed_login(conn, scope, identifier):
    _check_and_bump(conn, scope, f"ident:{identifier.lower()}", MAX_ATTEMPTS, IDENT_WINDOW_MIN, LOCKOUT_MIN, bump=True)
    _check_and_bump(conn, scope, f"ip:{_client_ip()}", MAX_IP_ATTEMPTS, IP_WINDOW_MIN, IP_LOCKOUT_MIN, bump=True)


def reset_attempts(conn, scope, identifier):
    conn.execute("DELETE FROM auth_attempts WHERE scope=? AND identifier=?", (scope, f"ident:{identifier.lower()}"))
    conn.execute("DELETE FROM auth_attempts WHERE scope=? AND identifier=?", (scope, f"ip:{_client_ip()}"))


# ---------------------------------------------------------------- generic rate limiting
#
# Reuses the same auth_attempts table as login lockout, but as a plain counter
# rather than a "fail enough times and get locked out" gate - every call counts,
# not just failures. Used to stop one IP from spinning up new free stores just to
# keep resetting a fresh $2,500 Starter cap every time the last one fills up.

def rate_limit_ok(conn, scope, identifier, max_count, window_minutes):
    """True (and records the hit) if identifier is still under max_count calls to
    this scope within window_minutes; False if it's already at the limit."""
    row = conn.execute("SELECT * FROM auth_attempts WHERE scope=? AND identifier=?", (scope, identifier)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO auth_attempts (scope, identifier, attempt_count, window_start) VALUES (?, ?, 1, ?)",
            (scope, identifier, _now().isoformat()),
        )
        return True
    window_start = datetime.fromisoformat(row["window_start"])
    if _now() - window_start > timedelta(minutes=window_minutes):
        conn.execute(
            "UPDATE auth_attempts SET attempt_count=1, window_start=?, locked_until=NULL, updated_at=CURRENT_TIMESTAMP WHERE scope=? AND identifier=?",
            (_now().isoformat(), scope, identifier),
        )
        return True
    if row["attempt_count"] >= max_count:
        return False
    conn.execute(
        "UPDATE auth_attempts SET attempt_count=attempt_count+1, updated_at=CURRENT_TIMESTAMP WHERE scope=? AND identifier=?",
        (scope, identifier),
    )
    return True


def signup_allowed(conn, max_count=3, window_minutes=1440):
    """At most max_count new stores per IP per window_minutes (default: 3/day).
    Doesn't stop someone determined to switch networks, but it kills the easy
    version of the exploit - refreshing and resubmitting the signup form to keep
    getting free $2,500/mo caps."""
    return rate_limit_ok(conn, "signup", f"ip:{_client_ip()}", max_count, window_minutes)


# ---------------------------------------------------------------- bearer-token auth
#
# Replaces Flask's cookie session for the API. A cross-origin split (static
# frontend on one domain, API on another) makes cookie-based sessions fragile -
# SameSite=None+Secure is required, third-party cookie blocking keeps getting
# stricter in browsers, and CSRF defenses built for same-origin forms don't map
# cleanly onto that. A bearer token in an Authorization header has neither
# problem: the browser never sends it automatically, so a malicious page on
# another origin has no ambient credential to ride along on in the first place -
# there's nothing to forge because nothing is sent unless the frontend's own JS
# explicitly attaches it.

def _hash_token(raw_token):
    return hashlib.sha256(raw_token.encode()).hexdigest()


def create_session(conn, store_id=None, is_owner=False, owner_2fa_pending=False, lifetime_hours=12):
    """Returns the raw token (shown to the client exactly once - only its hash is
    stored). owner_2fa_pending sessions get a short lifetime since they're only
    good for completing the 2FA step, not for actually doing anything yet."""
    raw_token = secrets.token_urlsafe(32)
    now = _now()
    expires_at = (now + timedelta(hours=lifetime_hours)).isoformat()
    # created_at/last_seen_at set explicitly (not left to SQLite's own
    # CURRENT_TIMESTAMP default) - that default is a naive "YYYY-MM-DD HH:MM:SS"
    # string with no timezone, which can't be subtracted from the timezone-aware
    # datetimes _now() produces everywhere else in this file.
    conn.execute(
        "INSERT INTO api_sessions (token_hash, store_id, is_owner, owner_2fa_pending, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (_hash_token(raw_token), store_id, int(is_owner), int(owner_2fa_pending), now.isoformat(), now.isoformat(), expires_at),
    )
    return raw_token


def get_session(conn, raw_token):
    """The session row for this token if it's valid and not expired, else None.
    Does NOT check idle timeout or 2FA-pending status - callers (require_store_auth
    / require_owner_auth) apply those, since what counts as "still good enough"
    differs between a store session and an owner one."""
    if not raw_token:
        return None
    row = conn.execute("SELECT * FROM api_sessions WHERE token_hash=?", (_hash_token(raw_token),)).fetchone()
    if not row:
        return None
    if datetime.fromisoformat(row["expires_at"]) < _now():
        return None
    return row


def touch_session(conn, session_row, max_idle_minutes):
    """True (and bumps last_seen_at) if still within its idle window; False once
    it's gone stale from inactivity - the same idle-logout behavior the old cookie
    session had, just tracked in the DB instead of the cookie itself."""
    last_seen = datetime.fromisoformat(session_row["last_seen_at"])
    if _now() - last_seen > timedelta(minutes=max_idle_minutes):
        return False
    conn.execute("UPDATE api_sessions SET last_seen_at=? WHERE id=?", (_now().isoformat(), session_row["id"]))
    return True


def upgrade_session_to_owner(conn, session_row, lifetime_hours=12):
    """Used right after a 2FA code checks out: turns a short-lived
    owner_2fa_pending session into a real, full-lifetime owner session, keeping
    the same token rather than issuing a new one."""
    expires_at = (_now() + timedelta(hours=lifetime_hours)).isoformat()
    conn.execute(
        "UPDATE api_sessions SET owner_2fa_pending=0, expires_at=?, last_seen_at=? WHERE id=?",
        (expires_at, _now().isoformat(), session_row["id"]),
    )


def delete_session(conn, raw_token):
    if raw_token:
        conn.execute("DELETE FROM api_sessions WHERE token_hash=?", (_hash_token(raw_token),))


def bearer_token_from_header(auth_header):
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    return auth_header[len("Bearer "):].strip() or None


# ---------------------------------------------------------------- audit log

def log_event(conn, actor_type, actor_label, action, detail=""):
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_label, action, detail, ip) VALUES (?, ?, ?, ?, ?)",
        (actor_type, actor_label, action, detail, _client_ip()),
    )


# ---------------------------------------------------------------- upload validation

# Magic-byte signatures - checked in addition to the extension so a renamed
# .html/.svg/.php can't be smuggled in through an "image" upload field.
_IMAGE_SIGNATURES = {
    b"\xff\xd8\xff": "jpg",
    b"\x89PNG\r\n\x1a\n": "png",
    b"GIF87a": "gif",
    b"GIF89a": "gif",
    b"RIFF": "webp",  # WEBP is RIFF....WEBP - checked more precisely below
}
ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}


def validate_image_upload(file_storage):
    """Returns True if this looks like a genuine image file the app is willing to
    save to disk and later serve back out. Raises nothing - caller decides what
    to do with a False (flash a message, skip the save, etc)."""
    if not file_storage or not file_storage.filename:
        return False
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return False

    head = file_storage.stream.read(16)
    file_storage.stream.seek(0)
    if head.startswith(b"\xff\xd8\xff"):
        ok = ext in ("jpg", "jpeg")
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        ok = ext == "png"
    elif head.startswith(b"GIF87a") or head.startswith(b"GIF89a"):
        ok = ext == "gif"
    elif head.startswith(b"RIFF") and b"WEBP" in head:
        ok = ext == "webp"
    else:
        ok = False
    return ok


def safe_upload_name(prefix):
    """A collision-proof, unguessable filename - never trust the original
    filename beyond its extension, which validate_image_upload already checked."""
    return f"{prefix}_{secrets.token_hex(8)}"
