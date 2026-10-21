import sqlite3
import os
import secrets
import string
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(__file__), "peltdev.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS leads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- 'service' lead (custom build inquiry)
    description TEXT,
    email TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    subject TEXT,
    message TEXT NOT NULL,
    store_subdomain TEXT,               -- optional: which store this is about
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS stores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain TEXT UNIQUE NOT NULL,     -- e.g. "chaseslawnwork" -> chaseslawnwork.peltdev.com
    business_name TEXT,
    owner_email TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_physical INTEGER NOT NULL DEFAULT 0,   -- 1 = ships/needs shipping info, 0 = digital/no shipping
    setup_paid INTEGER NOT NULL DEFAULT 0,    -- has the $25 CAD setup fee cleared (via Helcim)
    setup_helcim_transaction_id TEXT,
    theme_color TEXT DEFAULT '#E31C3D',       -- store's chosen accent, picked from a small preset palette
    banner_image TEXT,
    about_text TEXT,
    story TEXT,
    terms_accepted_at TEXT,
    -- storefront customization (added for the amazing-customization pass)
    tagline TEXT,                             -- short one-liner shown under the store name
    logo_image TEXT,                          -- small square mark, separate from the wide banner
    font_choice TEXT DEFAULT 'signature',     -- key into FONT_PAIRINGS in app.py
    layout_style TEXT DEFAULT 'grid',         -- 'grid' or 'list' product layout
    accent_style TEXT DEFAULT 'rounded',      -- 'rounded' or 'sharp' corner radius
    social_instagram TEXT,
    social_website TEXT,
    -- plan / revenue cap: everyone starts on 'starter' (free, capped). A store stays
    -- on a paid plan only while plan_renews_at is in the future - once it lapses,
    -- effective_plan_key() in app.py treats the store as 'starter' again.
    plan TEXT NOT NULL DEFAULT 'starter',
    plan_started_at TEXT,
    plan_renews_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- One row per successful plan payment (upgrade or renewal), charged to the
-- PLATFORM's own Helcim account - this is Jude's revenue, separate from anything
-- flowing through a seller's own connected Helcim account.
CREATE TABLE IF NOT EXISTS plan_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    plan TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    helcim_transaction_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Usage-based billing for the Scale plan: one row per calendar month a store has
-- been on Scale, generated lazily (the first time anything looks) rather than by a
-- cron job. amount_cents is max(1% of that month's paid sales, the plan minimum) -
-- see PLANS["scale"] in app.py. A store stays on Scale only while it doesn't have
-- an unpaid invoice older than GRACE_DAYS - see effective_plan_key().
CREATE TABLE IF NOT EXISTS plan_invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    amount_cents INTEGER NOT NULL,
    paid INTEGER NOT NULL DEFAULT 0,
    paid_at TEXT,
    helcim_transaction_id TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_plan_invoices_store_period ON plan_invoices(store_id, period_start);

-- Bearer-token sessions for the API. Cross-origin cookies (GitHub Pages calling a
-- Cloudflare-tunneled API on a different domain) are fragile - Safari/Chrome both
-- restrict third-party cookies more every year, and cross-site cookies need
-- SameSite=None+Secure plus careful CSRF handling. A bearer token in an
-- Authorization header sidesteps all of that: the browser never attaches it
-- automatically, so there's nothing for a malicious page to ride along on (no CSRF
-- token dance needed either - see security.py). Only token_hash is stored, never
-- the raw token, same principle as password hashing.
CREATE TABLE IF NOT EXISTS api_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT NOT NULL UNIQUE,
    store_id INTEGER,                          -- NULL for an owner session
    is_owner INTEGER NOT NULL DEFAULT 0,
    owner_2fa_pending INTEGER NOT NULL DEFAULT 0,  -- password checked, code not yet verified
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_api_sessions_store ON api_sessions(store_id);

-- Holds a Helcim secret_token (and any extra context) between /init and
-- /confirm for a single in-flight payment - setup fee, plan upgrade, invoice
-- payment, or a customer's order payment. Keyed by a one-time ref rather than
-- stashed on the login session row, so two payments in flight at once (two
-- browser tabs, a retried request) can never stomp on each other's token.
-- Deleted as soon as it's consumed (or naturally goes stale otherwise - rows
-- here are meant to live for seconds to minutes, not longer).
CREATE TABLE IF NOT EXISTS pending_payments (
    ref TEXT PRIMARY KEY,
    kind TEXT NOT NULL,               -- 'setup_fee' | 'plan_upgrade' | 'plan_invoice' | 'order'
    store_id INTEGER,
    order_id INTEGER,
    secret_token TEXT NOT NULL,
    extra TEXT,                        -- JSON blob for kind-specific context (e.g. plan_key, charge_cents)
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Each seller's OWN Helcim merchant account, so their customers' money goes straight
-- to their own bank and never touches the platform's Helcim account.
CREATE TABLE IF NOT EXISTS store_payment_settings (
    store_id INTEGER PRIMARY KEY REFERENCES stores(id),
    helcim_account_id TEXT,
    helcim_api_token_encrypted TEXT,   -- encrypted, see crypto_utils.py
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    name TEXT NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL,
    image_path TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    customer_name TEXT,
    customer_email TEXT,
    items_json TEXT NOT NULL,          -- [{product_id, name, qty, price_cents}]
    total_cents INTEGER NOT NULL,
    needs_shipping INTEGER NOT NULL DEFAULT 0,
    shipping_address TEXT,
    paid INTEGER NOT NULL DEFAULT 0,   -- confirmed via Helcim (seller's own account)
    helcim_transaction_id TEXT,
    status TEXT NOT NULL DEFAULT 'awaiting_payment',  -- awaiting_payment -> paid -> confirmed -> shipped
    tracking_number TEXT,
    tracking_carrier TEXT,
    terms_accepted_at TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Brute-force protection: every failed login (owner portal or seller admin) records
-- a hit here, keyed by scope + identifier (email/username) and separately by scope + IP,
-- so a lockout survives a restart instead of living only in memory.
CREATE TABLE IF NOT EXISTS auth_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,               -- 'owner' or 'store'
    identifier TEXT NOT NULL,          -- e.g. 'ident:jude' or 'ip:203.0.113.4'
    attempt_count INTEGER NOT NULL DEFAULT 1,
    window_start TEXT NOT NULL,
    locked_until TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_attempts_scope_ident ON auth_attempts(scope, identifier);

-- Security/audit trail: logins (success + failure), lockouts, and sensitive admin
-- actions (payment settings changed, order status changed, etc). Shown in the
-- owner portal's Security tab.
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_type TEXT NOT NULL,          -- 'owner' | 'store' | 'system'
    actor_label TEXT,                  -- username/email/store subdomain, for display
    action TEXT NOT NULL,
    detail TEXT,
    ip TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Automatic e-transfer verification: where to read each store's deposit emails
-- (IMAP app password, encrypted at rest) and a ledger of every email already
-- looked at, so one email can never pay two orders or be replayed.
CREATE TABLE IF NOT EXISTS store_email_settings (
    store_id INTEGER PRIMARY KEY REFERENCES stores(id),
    imap_host TEXT NOT NULL,
    imap_user TEXT NOT NULL,
    imap_pass_encrypted TEXT NOT NULL,
    last_checked_at TEXT,
    last_error TEXT,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS processed_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    order_id INTEGER,
    outcome TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(store_id, message_id)
);

-- Payments owed TO THE PLATFORM (setup fee, plan upgrades, Scale invoices) by
-- e-transfer or PayPal.me. Confirmed automatically by reading the owner's
-- notification inbox - same checks as store orders (see etransfer_verifier.py).
CREATE TABLE IF NOT EXISTS platform_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    store_id INTEGER NOT NULL REFERENCES stores(id),
    kind TEXT NOT NULL,              -- 'setup_fee' | 'plan_upgrade' | 'plan_invoice'
    plan_key TEXT,
    invoice_id INTEGER,
    method TEXT NOT NULL,            -- 'etransfer' | 'paypal'
    ref TEXT NOT NULL,
    base_cents INTEGER NOT NULL,     -- what the fee actually is
    expected_cents INTEGER NOT NULL, -- base + a few cents if needed to make the amount unique
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    paid_at TEXT
);
"""

# Columns added after the original release - applied with ALTER TABLE for anyone
# upgrading an existing peltdev.db in place. Safe to re-run; each is guarded.
MIGRATIONS = [
    ("stores", "tagline", "TEXT"),
    ("stores", "logo_image", "TEXT"),
    ("stores", "font_choice", "TEXT DEFAULT 'signature'"),
    ("stores", "layout_style", "TEXT DEFAULT 'grid'"),
    ("stores", "accent_style", "TEXT DEFAULT 'rounded'"),
    ("stores", "social_instagram", "TEXT"),
    ("stores", "social_website", "TEXT"),
    ("stores", "plan", "TEXT NOT NULL DEFAULT 'starter'"),
    ("stores", "plan_started_at", "TEXT"),
    ("stores", "plan_renews_at", "TEXT"),
    ("stores", "etransfer_email", "TEXT"),
    ("stores", "suspended_at", "TEXT"),
    ("stores", "suspended_reason", "TEXT"),
    ("stores", "banner_style", "TEXT NOT NULL DEFAULT 'image'"),
    ("stores", "card_style", "TEXT NOT NULL DEFAULT 'shadow'"),
    ("stores", "page_look", "TEXT NOT NULL DEFAULT 'dark'"),
    ("stores", "button_style", "TEXT NOT NULL DEFAULT 'solid'"),
    ("stores", "announcement", "TEXT"),
    ("stores", "order_button_text", "TEXT"),
    ("stores", "grid_columns", "INTEGER NOT NULL DEFAULT 2"),
    ("stores", "hero_align", "TEXT NOT NULL DEFAULT 'left'"),
    ("stores", "footer_note", "TEXT"),
    ("orders", "payment_ref", "TEXT"),
    ("orders", "payment_method", "TEXT NOT NULL DEFAULT 'helcim'"),
    ("orders", "etransfer_amount_cents", "INTEGER"),   # exact amount the buyer must send (etransfer OR paypal orders)
    ("orders", "shipping_cents", "INTEGER NOT NULL DEFAULT 0"),  # the store's flat shipping rate, frozen at order time
    ("orders", "shipping_country", "TEXT"),
    ("stores", "shipping_flat_cents", "INTEGER NOT NULL DEFAULT 0"),
    ("stores", "ships_to", "TEXT NOT NULL DEFAULT 'ca'"),  # 'ca' | 'ca_us' | 'worldwide'
    ("stores", "paypal_me", "TEXT"),
    ("stores", "paypal_email", "TEXT"),
    ("stores", "etransfer_discount_pct", "INTEGER NOT NULL DEFAULT 0"),
]


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def _run_migrations(conn):
    for table, column, coltype in MIGRATIONS:
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
        if column not in existing:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")


def init_db():
    with get_db() as conn:
        conn.executescript(SCHEMA)
        _run_migrations(conn)


def gen_ref(prefix="PELT"):
    """Short human-readable reference code (still used as an order-friendly display id)."""
    alphabet = string.ascii_uppercase + string.digits
    code = "".join(secrets.choice(alphabet) for _ in range(6))
    return f"{prefix}-{code}"
