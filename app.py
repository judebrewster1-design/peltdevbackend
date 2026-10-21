"""
Peltier Development - JSON API backend.

This used to be a server-rendered Flask app (Jinja templates in
frontend/templates/). It's now a pure JSON API: the frontend is a static
single-page app (frontend/index.html + frontend/app.js) meant to be hosted on
GitHub Pages, calling this API wherever it's actually running (e.g. behind a
Cloudflare Tunnel). See the README for the full "why" behind that split and
the auth model change (bearer tokens instead of cookies) it required.

Every route below is a direct port of the old template-rendering route with
the same name in spirit - same business logic, same security checks, same
money-handling rules - just returning JSON instead of rendering HTML.
"""
import csv
import hmac
import io
import os
import re
import json
import secrets as secrets_mod
from datetime import datetime, date, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, abort, Response, g, send_from_directory
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from db import get_db, init_db, gen_ref
import crypto_utils
import helcim
import security

try:
    import pyotp
except ImportError:
    pyotp = None  # optional 2FA for owner login - see OWNER_TOTP_SECRET below

APP_ROOT = os.path.dirname(os.path.abspath(__file__))          # .../backend
PROJECT_ROOT = os.path.dirname(APP_ROOT)                        # .../ (one level up)
FRONTEND_ROOT = os.path.join(PROJECT_ROOT, "frontend")

from dotenv import load_dotenv
load_dotenv(os.path.join(PROJECT_ROOT, ".env"))

UPLOAD_DIR = os.path.join(FRONTEND_ROOT, "static", "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

ROOT_DOMAIN = os.environ.get("ROOT_DOMAIN", "peltdev.com")
SETUP_FEE_DOLLARS = 25.00

# The GitHub Pages origin (or origins, comma-separated) allowed to call this API.
# "*" works for local development but should be your real Pages URL in
# production - e.g. "https://yourname.github.io" (no trailing slash, no path).
FRONTEND_ORIGIN = os.environ.get("FRONTEND_ORIGIN", "*")
_allowed_origins = [o.strip() for o in FRONTEND_ORIGIN.split(",") if o.strip()]

# ---------------------------------------------------------------- plans / revenue cap
#
# Every store starts on Starter (free) capped at $2,500 of paid sales per calendar
# month. To keep selling past that, the seller pays for Growth or Scale - charged
# to the PLATFORM's own Helcim account (this is Jude's revenue, not the seller's),
# via ACH by default. Helcim's published ACH/EFT rate is 0.5% + $0.25/transaction,
# capped at $6, and there's no Helcim monthly fee at all - so at these prices the
# take-home margin is roughly:
#   Growth $35/mo flat     -> Helcim fee ~$0.43 -> ~$34.57 net (~98.8%)
#   Scale $49/mo minimum   -> Helcim fee ~$0.50 -> ~$48.50 net (~99.0%)
# (Card-rate ACH would run closer to 2.5%+$0.25 - noticeably worse margin - which is
# why HELCIM_PAYMENT_METHOD stays on 'ach' for this. See helcim.py.)
#
# Scale is deliberately usage-based (1% of that store's sales, $49/mo floor) rather
# than a flat "unlimited" price: a flat price for uncapped sales means a huge-volume
# store pays the same as one barely above the floor, which caps your upside right
# when a seller is worth the most. A percentage of sales scales your take with
# theirs automatically, no matter how many transactions they run.
#
# There's no card-on-file/auto-charge here on purpose - storing card numbers pulls
# this app into a much bigger PCI compliance scope for not much gain. Growth is a
# manual 30-day pass (re-pay via the same HelcimPay.js flow used for the setup fee,
# lapses back to Starter if not renewed in time). Scale is billed as a monthly
# invoice generated lazily off the orders this app already tracks - see
# get_or_create_scale_invoice() - and access lapses back to Starter if an invoice
# goes more than GRACE_DAYS unpaid.
PLAN_PERIOD_DAYS = 30
GRACE_DAYS = 5
PLANS = {
    "starter": {"label": "Starter", "kind": "flat", "price_dollars": 0.0, "cap_cents": 250_000,
                "tagline": "Free — up to $2,500 in sales per calendar month."},
    "growth":  {"label": "Growth", "kind": "flat", "price_dollars": 35.00, "cap_cents": 1_000_000,
                "fee_credit_cap_cents": 2000,
                "tagline": "$35/mo — up to $10,000 in sales per month, and we cover up to $20/mo of your own Helcim processing fees."},
    "scale":   {"label": "Scale", "kind": "usage", "price_dollars": 49.00, "percent": 0.01, "cap_cents": None,
                "tagline": "1% of what you sell, $49/mo minimum — unlimited, no matter how many transactions."},
    # Not purchasable by anyone - only the owner API can set a store to this (see
    # owner_comp_store below). No bill, ever, unless an owner takes it back.
    "comp":    {"label": "Comp", "kind": "comp", "price_dollars": 0.0, "cap_cents": None, "hidden": True,
                "tagline": "Gifted directly by the platform owner — free, unlimited, no expiry."},
}
PLAN_ORDER = ["starter", "growth", "scale"]  # deliberately excludes "comp" - nothing here is self-serve


def estimated_helcim_fee_cents(amount_cents):
    """What Helcim's own published rate would charge for one transaction of this
    size, under whichever payment method this deployment actually uses."""
    if helcim.HELCIM_PAYMENT_METHOD == "cc":
        return round(amount_cents * 0.0249) + 25
    return min(round(amount_cents * 0.005) + 25, 600)  # ACH: 0.5% + $0.25, capped at $6


def growth_fee_credit_cents(conn, store):
    """Sum of estimated Helcim fees on this store's own sales since its current
    Growth billing period started, capped at PLANS['growth']['fee_credit_cap_cents'].
    Zero on a first-time activation (there's no prior Growth period to credit) or for
    any store not currently on Growth."""
    cap = PLANS["growth"].get("fee_credit_cap_cents", 0)
    if cap <= 0 or store["plan"] != "growth" or not store["plan_renews_at"]:
        return 0
    try:
        period_start = (datetime.fromisoformat(store["plan_renews_at"]) - timedelta(days=PLAN_PERIOD_DAYS)).isoformat()
    except ValueError:
        return 0
    rows = conn.execute(
        "SELECT total_cents FROM orders WHERE store_id=? AND paid=1 AND created_at >= ?",
        (store["id"], period_start),
    ).fetchall()
    total_fee = sum(estimated_helcim_fee_cents(r["total_cents"]) for r in rows)
    return min(total_fee, cap)


DEMO_VIDEO_ID = os.environ.get("DEMO_VIDEO_ID", "dQw4w9WgXcQ")  # swap for your real walkthrough video

# All storefronts created under this platform stop serving customers after this date.
# Defaults to the next June 30th from whenever the app starts - override with
# SITE_CUTOFF_DATE=YYYY-MM-DD if you meant a specific year.
_cutoff_env = os.environ.get("SITE_CUTOFF_DATE")
if _cutoff_env:
    SITE_CUTOFF_DATE = date.fromisoformat(_cutoff_env)
else:
    today = date.today()
    year = today.year if today <= date(today.year, 6, 30) else today.year + 1
    SITE_CUTOFF_DATE = date(year, 6, 30)

OWNER_USERNAME = os.environ.get("OWNER_USERNAME", "jude")
OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD")  # set this - no hardcoded default password
# Optional TOTP second factor for owner login (real money and every seller's data lives
# behind it). Generate a secret once with:
#   python3 -c "import pyotp;print(pyotp.random_base32())"
# put it in OWNER_TOTP_SECRET, and add it to an authenticator app. Leave unset to run
# owner login as password-only.
OWNER_TOTP_SECRET = os.environ.get("OWNER_TOTP_SECRET")


def _owner_2fa_enabled():
    return bool(OWNER_TOTP_SECRET and pyotp)


THEME_PRESETS = [
    {"name": "Signature red", "hex": "#E31C3D"},
    {"name": "Ocean", "hex": "#1C7DE0"},
    {"name": "Forest", "hex": "#1F9D55"},
    {"name": "Amber", "hex": "#E8A93F"},
    {"name": "Violet", "hex": "#8B5CF6"},
    {"name": "Slate", "hex": "#64748B"},
    {"name": "Teal", "hex": "#14B8A6"},
    {"name": "Magenta", "hex": "#EC4899"},
    {"name": "Indigo", "hex": "#4F46E5"},
]

# Curated font pairings for storefront customization - each maps to a real Google
# Fonts request and a CSS var override, so picking one instantly reskins headings/body.
FONT_PAIRINGS = {
    "signature": {"label": "Signature (Space Grotesk / IBM Plex Sans)", "gfonts": "Space+Grotesk:wght@500;600;700&family=IBM+Plex+Sans:wght@400;500;600", "heading": "'Space Grotesk', sans-serif", "body": "'IBM Plex Sans', system-ui, sans-serif"},
    "editorial": {"label": "Editorial (Playfair Display / Inter)", "gfonts": "Playfair+Display:wght@600;700&family=Inter:wght@400;500;600", "heading": "'Playfair Display', serif", "body": "'Inter', system-ui, sans-serif"},
    "friendly": {"label": "Friendly (Poppins / Nunito Sans)", "gfonts": "Poppins:wght@600;700&family=Nunito+Sans:wght@400;600", "heading": "'Poppins', sans-serif", "body": "'Nunito Sans', system-ui, sans-serif"},
    "technical": {"label": "Technical (Chivo Mono / Roboto)", "gfonts": "Chivo+Mono:wght@500;600&family=Roboto:wght@400;500", "heading": "'Chivo Mono', monospace", "body": "'Roboto', system-ui, sans-serif"},
    "bold": {"label": "Bold (Archivo Black / Work Sans)", "gfonts": "Archivo+Black&family=Work+Sans:wght@400;500;600", "heading": "'Archivo Black', sans-serif", "body": "'Work Sans', system-ui, sans-serif"},
    "elegant": {"label": "Elegant (Cormorant Garamond / Jost)", "gfonts": "Cormorant+Garamond:wght@600;700&family=Jost:wght@400;500", "heading": "'Cormorant Garamond', serif", "body": "'Jost', system-ui, sans-serif"},
}
LAYOUT_STYLES = [{"key": "grid", "label": "Grid — a browsable product wall"}, {"key": "list", "label": "List — one item per row, more detail up front"}]
ACCENT_STYLES = [{"key": "rounded", "label": "Rounded — soft corners"}, {"key": "sharp", "label": "Sharp — square corners"}]
BANNER_STYLES = [
    {"key": "image", "label": "Photo — your own uploaded banner"},
    {"key": "gradient", "label": "Gradient — built from your accent color, no photo needed"},
    {"key": "solid", "label": "Solid — flat accent-colored band"},
]
CARD_STYLES = [
    {"key": "shadow", "label": "Shadow — soft lift off the page"},
    {"key": "flat", "label": "Flat — minimal, no depth"},
    {"key": "outline", "label": "Outline — bordered, no fill"},
]

# Ready-made starting points: one click bundles a color + font + layout + corner
# style + banner treatment + card style into a complete, coherent look, the way
# a real website builder's theme gallery works - a seller can still fine-tune
# any individual field afterward, this just picks good combinations to start
# from instead of making someone assemble a look from six separate dropdowns.
PAGE_LOOKS = [
    {"key": "dark", "label": "Dark — deep navy, glowing accents", "bg": "#0A0E14", "surface": "#12161F", "surface2": "#1A2030", "text": "#E8ECF1", "muted": "#8A94A6", "border": "#232A3A"},
    {"key": "light", "label": "Light — crisp white, clean and modern", "bg": "#FFFFFF", "surface": "#F6F7F9", "surface2": "#ECEEF2", "text": "#11141A", "muted": "#566074", "border": "#DDE1E8"},
    {"key": "cream", "label": "Cream — warm paper, handmade feel", "bg": "#FBF6EC", "surface": "#FFFDF8", "surface2": "#F1E8D6", "text": "#2B2118", "muted": "#705F4C", "border": "#E3D8C2"},
    {"key": "mist", "label": "Mist — cool pale blue-grey, airy", "bg": "#F2F5FA", "surface": "#FFFFFF", "surface2": "#E6EBF3", "text": "#141B2B", "muted": "#566177", "border": "#D8DFEB"},
    {"key": "noir", "label": "Noir — true black with warm ivory text", "bg": "#0B0B0C", "surface": "#151516", "surface2": "#202022", "text": "#F4EFE4", "muted": "#A39B8A", "border": "#2E2C28"},
]
BUTTON_STYLES = [
    {"key": "solid", "label": "Solid — filled accent, softly rounded"},
    {"key": "pill", "label": "Pill — fully rounded, friendly"},
    {"key": "outline", "label": "Outline — accent border, no fill"},
    {"key": "block", "label": "Block — square, bold, uppercase"},
]

THEMES = [
    {"key": "bold-modern", "name": "Bold Modern", "blurb": "Stark white, electric orange, heavy type. Loud and confident.", "theme_color": "#FF4A1C", "font_choice": "bold", "layout_style": "grid", "accent_style": "sharp", "banner_style": "solid", "card_style": "outline", "page_look": "light", "button_style": "block"},
    {"key": "midnight-market", "name": "Midnight Market", "blurb": "Dark, techy and compact. Great for gadgets and gaming.", "theme_color": "#8B5CF6", "font_choice": "technical", "layout_style": "list", "accent_style": "sharp", "banner_style": "gradient", "card_style": "outline", "page_look": "dark", "button_style": "outline"},
    {"key": "sunset-studio", "name": "Sunset Studio", "blurb": "Warm and welcoming. Made for crafts, bakes and art.", "theme_color": "#E8892B", "font_choice": "friendly", "layout_style": "grid", "accent_style": "rounded", "banner_style": "gradient", "card_style": "shadow", "page_look": "cream", "button_style": "pill"},
    {"key": "minimal-mono", "name": "Minimal Mono", "blurb": "Quiet, editorial, all business. Lets the products talk.", "theme_color": "#2B3140", "font_choice": "technical", "layout_style": "list", "accent_style": "sharp", "banner_style": "solid", "card_style": "flat", "page_look": "light", "button_style": "solid"},
    {"key": "botanical", "name": "Botanical", "blurb": "Soft greens on paper. Plants, wellness, natural goods.", "theme_color": "#2F8F5B", "font_choice": "editorial", "layout_style": "grid", "accent_style": "rounded", "banner_style": "gradient", "card_style": "shadow", "page_look": "cream", "button_style": "pill"},
    {"key": "neon-nights", "name": "Neon Nights", "blurb": "Hot pink on black. Streetwear, music and nightlife.", "theme_color": "#FF2E93", "font_choice": "bold", "layout_style": "grid", "accent_style": "sharp", "banner_style": "gradient", "card_style": "outline", "page_look": "noir", "button_style": "block"},
    {"key": "ocean-breeze", "name": "Ocean Breeze", "blurb": "Fresh and friendly blue. Easy for any small shop.", "theme_color": "#1C7DE0", "font_choice": "friendly", "layout_style": "grid", "accent_style": "rounded", "banner_style": "gradient", "card_style": "shadow", "page_look": "mist", "button_style": "solid"},
    {"key": "luxe-noir", "name": "Luxe Noir", "blurb": "Black and gold with a serif voice. Jewellery and premium goods.", "theme_color": "#C9A24A", "font_choice": "elegant", "layout_style": "grid", "accent_style": "sharp", "banner_style": "solid", "card_style": "flat", "page_look": "noir", "button_style": "outline"},
    {"key": "indigo-editorial", "name": "Indigo Editorial", "blurb": "Magazine layout, deep indigo. Prints, books and stationery.", "theme_color": "#4F46E5", "font_choice": "editorial", "layout_style": "list", "accent_style": "rounded", "banner_style": "gradient", "card_style": "flat", "page_look": "mist", "button_style": "solid"},
]

SHIP_TO_OPTIONS = [
    {"key": "ca", "label": "Canada only", "countries": ["CA"]},
    {"key": "ca_us", "label": "Canada & United States", "countries": ["CA", "US"]},
    {"key": "worldwide", "label": "Worldwide", "countries": None},  # None = no restriction
]
SHIP_TO_COUNTRIES = {o["key"]: o["countries"] for o in SHIP_TO_OPTIONS}

# Loose, deliberately forgiving validation - this exists to catch obvious typos
# (an empty field, three random digits) before an order ships to a nonexistent
# address, not to be the single source of truth for every postal system on
# Earth. Anything outside CA/US gets a basic non-empty check only.
POSTAL_CODE_RE = {
    "CA": re.compile(r"^[A-Za-z]\d[A-Za-z][ -]?\d[A-Za-z]\d$"),
    "US": re.compile(r"^\d{5}(-\d{4})?$"),
}

SUBDOMAIN_RE = re.compile(r"^[a-z]+$")  # letters only, per spec - no digits/hyphens/special chars

# Storefronts live at the site root now (peltdev.com/#/<name>, not /#/store/<name>),
# so a store's own name shares the same namespace as every top-level page this
# frontend serves. A seller named "admin" or "login" would make their own
# storefront permanently unreachable (that path always resolves to the real
# admin/login page first) - these names are blocked at signup for exactly that
# reason, not for any content-moderation purpose.
RESERVED_SUBDOMAINS = {
    "story", "terms", "privacy", "support", "create", "login", "logout",
    "pay", "admin", "owner", "api", "www", "app", "checkout", "order",
}
HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024  # 8MB upload cap

# CORS: only the configured frontend origin(s) can call this API from a browser.
# supports_credentials is False on purpose - auth is a bearer token in a header,
# never a cookie, so there's no ambient credential for the browser to attach and
# nothing that needs the credentials dance CORS otherwise requires.
# Every seller storefront lives on its own subdomain (shop.peltdev.com), which is a
# different browser origin from www.peltdev.com - so besides the explicit list,
# any https://<name>.<ROOT_DOMAIN> origin is allowed to call the API too.
if _allowed_origins == ["*"]:
    _cors_origins = "*"
else:
    _cors_origins = _allowed_origins + [re.compile(r"^https://[a-z0-9-]+\." + re.escape(ROOT_DOMAIN) + r"$")]
CORS(
    app,
    resources={r"/api/*": {"origins": _cors_origins}},
    supports_credentials=False,
    expose_headers=["Content-Disposition"],  # so the frontend can read the CSV filename on export downloads
)


@app.after_request
def _security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    if os.environ.get("FLASK_ENV") != "development":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return resp


@app.errorhandler(400)
def _bad_request(e):
    return jsonify({"error": getattr(e, "description", "Bad request.")}), 400


@app.errorhandler(404)
def _not_found(e):
    return jsonify({"error": "Not found."}), 404


init_db()


# ---------------------------------------------------------------- helpers

def money(cents):
    return f"${cents / 100:,.2f}"


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def site_is_cut_off():
    return date.today() > SITE_CUTOFF_DATE


def site_cutoff_label():
    return SITE_CUTOFF_DATE.strftime("%B %d, %Y").replace(" 0", " ")


def get_store_payment_settings(store_id):
    with get_db() as conn:
        return conn.execute(
            "SELECT * FROM store_payment_settings WHERE store_id=?", (store_id,)
        ).fetchone()


def _auto_verify_enabled(store_id):
    with get_db() as conn:
        return conn.execute("SELECT 1 FROM store_email_settings WHERE store_id=?", (store_id,)).fetchone() is not None


def _store_methods(store, conn):
    """Every way this store currently lets buyers pay, Helcim included whenever
    it's actually connected - Helcim isn't just a fallback for stores with
    nothing else set up, it's a real option a buyer can choose alongside
    PayPal/e-Transfer if the seller connected it. Checking this needs conn since
    Helcim's connection lives in store_payment_settings, a separate table from
    the stores row everything else here reads from."""
    m = []
    if store["paypal_me"]:
        m.append("paypal")
    if store["etransfer_email"]:
        m.append("etransfer")
    settings = conn.execute(
        "SELECT 1 FROM store_payment_settings WHERE store_id=? AND helcim_account_id IS NOT NULL", (store["id"],)
    ).fetchone()
    if settings:
        m.append("helcim")
    return m


def paypal_link(name, cents):
    return f"https://www.paypal.me/{name}/{cents / 100:.2f}CAD"


def _unique_expected_cents(conn, store_id, base_cents):
    """The exact amount a buyer must send. Normally the price itself; if another
    unpaid order for this store already expects that exact amount, add a cent (or a
    few) so the amount alone identifies the order even when the bank/PayPal email
    carries no memo."""
    taken = {r[0] for r in conn.execute(
        """SELECT COALESCE(etransfer_amount_cents, total_cents) FROM orders
           WHERE store_id=? AND paid=0 AND payment_method IN ('etransfer','paypal')
           AND created_at >= datetime('now','-72 hours')""", (store_id,)).fetchall()}
    amt, bump = base_cents, 0
    while amt in taken and bump < 99:
        bump += 1
        amt = base_cents + bump
    return amt


def store_to_dict(store, include_private=False):
    """The public-safe shape of a store row. include_private adds fields only the
    store's own owner (or the platform owner) should ever see."""
    d = {
        "id": store["id"],
        "subdomain": store["subdomain"],
        "business_name": store["business_name"],
        "is_physical": bool(store["is_physical"]),
        "theme_color": store["theme_color"],
        "banner_image": store["banner_image"],
        "logo_image": store["logo_image"],
        "tagline": store["tagline"],
        "about_text": store["about_text"],
        "font_choice": store["font_choice"] or "signature",
        "layout_style": store["layout_style"] or "grid",
        "accent_style": store["accent_style"] or "rounded",
        "banner_style": store["banner_style"] or "image",
        "card_style": store["card_style"] or "shadow",
        "page_look": store["page_look"] or "dark",
        "button_style": store["button_style"] or "solid",
        "announcement": store["announcement"],
        "order_button_text": store["order_button_text"],
        "grid_columns": store["grid_columns"] or 2,
        "hero_align": store["hero_align"] or "left",
        "footer_note": store["footer_note"],
        "shipping_flat_cents": store["shipping_flat_cents"] or 0,
        "ships_to": store["ships_to"] or "ca",
        "social_instagram": store["social_instagram"],
        "social_website": store["social_website"],
        # Public on purpose: a buyer needs this to actually pay for an e-transfer
        # order. It's a payout address the store owner chose to publish, not a
        # secret - same category as the theme color or the banner image.
        "etransfer_email": store["etransfer_email"],
        "paypal_me": store["paypal_me"],
        "etransfer_discount_pct": store["etransfer_discount_pct"] or 0,
    }
    if include_private:
        d.update({
            "owner_email": store["owner_email"],
            "setup_paid": bool(store["setup_paid"]),
            "created_at": store["created_at"],
            "plan": store["plan"] or "starter",
            "plan_started_at": store["plan_started_at"],
            "paypal_email": store["paypal_email"],
            "plan_renews_at": store["plan_renews_at"],
            "suspended": bool(store["suspended_at"]),
            "suspended_reason": store["suspended_reason"],
        })
    return d


def product_to_dict(p):
    return {
        "id": p["id"], "name": p["name"], "description": p["description"],
        "price_cents": p["price_cents"], "image_path": p["image_path"],
        "active": bool(p["active"]), "created_at": p["created_at"],
    }


def order_to_dict(o, include_shipping=False):
    """include_shipping mirrors the old template's rule: shipping/contact info
    (address, name, email) only ever goes out for orders that are actually paid.
    An unpaid order simply never gets those fields populated in the response."""
    d = {
        "id": o["id"], "total_cents": o["total_cents"], "paid": bool(o["paid"]),
        "status": o["status"], "needs_shipping": bool(o["needs_shipping"]),
        "tracking_number": o["tracking_number"], "tracking_carrier": o["tracking_carrier"],
        "created_at": o["created_at"], "items": json.loads(o["items_json"]),
        "payment_method": o["payment_method"] or "helcim", "payment_ref": o["payment_ref"],
        "etransfer_amount_cents": o["etransfer_amount_cents"],
        # The shipping charge itself (part of total_cents, broken out for display)
        # isn't address/contact info, so it's not gated behind include_shipping -
        # a buyer checking an unpaid order's total should still see what shipping
        # cost them, same as the item prices.
        "shipping_cents": o["shipping_cents"] or 0,
    }
    if include_shipping and o["paid"]:
        d.update({
            "customer_name": o["customer_name"], "customer_email": o["customer_email"],
            "shipping_address": o["shipping_address"], "shipping_country": o["shipping_country"],
        })
    return d


# ---------------------------------------------------------------- plan / revenue cap helpers

def _month_start_iso():
    return date.today().replace(day=1).isoformat()


def store_revenue_this_month(conn, store_id):
    row = conn.execute(
        "SELECT COALESCE(SUM(total_cents),0) t FROM orders WHERE store_id=? AND paid=1 AND date(created_at) >= ?",
        (store_id, _month_start_iso()),
    ).fetchone()
    return row["t"]


def get_or_create_scale_invoice(conn, store):
    """The most recently-completed calendar month's Scale invoice for this store, or
    None if the store wasn't on Scale for any part of that month. Generated lazily -
    whoever looks first (the seller's own GET /api/plan, or the enforcement check in
    effective_plan_key) causes it to be computed and stored, so nothing here needs a
    scheduled job. amount_cents is frozen once written; later orders in that same
    month don't change a bill that's already been issued."""
    plan_started = store["plan_started_at"]
    if not plan_started:
        return None
    today = date.today()
    period_end = today.replace(day=1) - timedelta(days=1)
    period_start = period_end.replace(day=1)
    try:
        started_date = datetime.fromisoformat(plan_started).date()
    except ValueError:
        return None
    if started_date > period_end:
        return None  # not on Scale for any part of the most recently completed month

    existing = conn.execute(
        "SELECT * FROM plan_invoices WHERE store_id=? AND period_start=?",
        (store["id"], period_start.isoformat()),
    ).fetchone()
    if existing:
        return existing

    revenue = conn.execute(
        "SELECT COALESCE(SUM(total_cents),0) t FROM orders WHERE store_id=? AND paid=1 AND date(created_at) BETWEEN ? AND ?",
        (store["id"], period_start.isoformat(), period_end.isoformat()),
    ).fetchone()["t"]
    amount_cents = max(round(revenue * PLANS["scale"]["percent"]), int(PLANS["scale"]["price_dollars"] * 100))
    cur = conn.execute(
        "INSERT INTO plan_invoices (store_id, period_start, period_end, amount_cents, paid) VALUES (?, ?, ?, ?, 0)",
        (store["id"], period_start.isoformat(), period_end.isoformat(), amount_cents),
    )
    return conn.execute("SELECT * FROM plan_invoices WHERE id=?", (cur.lastrowid,)).fetchone()


def effective_plan_key(store, conn):
    """The plan that actually applies right now.
    - Growth is time-based: only counts while plan_renews_at is still in the future.
    - Scale is invoice-based: only counts while it doesn't have an unpaid invoice
      older than GRACE_DAYS.
    Either way this quietly falls back to 'starter' (and its cap) once access
    lapses, rather than leaving a store on a paid tier for free."""
    plan = store["plan"] or "starter"
    if plan == "starter" or plan not in PLANS:
        return "starter"

    if plan == "comp":
        return "comp"  # gifted - no time limit, no invoice, no self-serve way in or out

    if plan == "growth":
        renews_at = store["plan_renews_at"]
        if not renews_at:
            return "starter"
        try:
            if datetime.fromisoformat(renews_at) < datetime.now(timezone.utc):
                return "starter"
        except ValueError:
            return "starter"
        return "growth"

    if plan == "scale":
        invoice = get_or_create_scale_invoice(conn, store)
        if invoice and not invoice["paid"]:
            due_by = date.fromisoformat(invoice["period_end"]) + timedelta(days=GRACE_DAYS)
            if date.today() > due_by:
                return "starter"
        return "scale"

    return "starter"


def plan_room_check(conn, store, additional_cents=0):
    """(ok, plan_key, used_cents, cap_cents). cap_cents is None for unlimited plans.
    additional_cents lets a caller ask 'is there room for one more order of this size'
    without a separate follow-up query."""
    plan_key = effective_plan_key(store, conn)
    cap_cents = PLANS[plan_key]["cap_cents"]
    used = store_revenue_this_month(conn, store["id"])
    if cap_cents is None:
        return True, plan_key, used, None
    return (used + additional_cents) <= cap_cents, plan_key, used, cap_cents


def _current_open_invoice(conn, store):
    """The most recent invoice that's still unpaid, if any - regardless of whether
    the grace period has already lapsed it back to Starter. A store can pay a
    lapsed invoice to get back onto Scale immediately."""
    if (store["plan"] or "starter") != "scale":
        return None
    return conn.execute(
        "SELECT * FROM plan_invoices WHERE store_id=? AND paid=0 ORDER BY period_start DESC LIMIT 1",
        (store["id"],),
    ).fetchone()


def plan_to_dict(key):
    p = dict(PLANS[key])
    p["key"] = key
    return p


# ---------------------------------------------------------------- auth (bearer tokens)
#
# See security.py's "bearer-token auth" section for the why. The short version:
# a token in the Authorization header, checked against a hash stored in
# api_sessions, replacing Flask's cookie session entirely.

def require_store_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = security.bearer_token_from_header(request.headers.get("Authorization"))
        with get_db() as conn:
            sess = security.get_session(conn, token)
            if not sess or not sess["store_id"] or sess["is_owner"]:
                return jsonify({"error": "Not authenticated."}), 401
            if not security.touch_session(conn, sess, max_idle_minutes=60):
                security.delete_session(conn, token)
                return jsonify({"error": "Session expired from inactivity — log in again."}), 401
            store = conn.execute("SELECT * FROM stores WHERE id=?", (sess["store_id"],)).fetchone()
        if not store:
            return jsonify({"error": "Store not found."}), 401
        if store["suspended_at"]:
            # Checked on every admin request, not just at login - a store suspended
            # mid-session loses access immediately rather than at next login.
            return jsonify({"error": "This account has been suspended." + (f" Reason: {store['suspended_reason']}" if store["suspended_reason"] else ""), "code": "suspended"}), 403
        g.store = store
        g.auth_token = token
        return fn(*args, **kwargs)
    return wrapper


def require_paid(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not g.store["setup_paid"]:
            return jsonify({"error": "Setup fee not paid yet.", "code": "setup_fee_required"}), 402
        return fn(*args, **kwargs)
    return wrapper


def require_owner_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = security.bearer_token_from_header(request.headers.get("Authorization"))
        with get_db() as conn:
            sess = security.get_session(conn, token)
            if not sess or not sess["is_owner"] or sess["owner_2fa_pending"]:
                return jsonify({"error": "Not authenticated."}), 401
            if not security.touch_session(conn, sess, max_idle_minutes=30):
                security.delete_session(conn, token)
                return jsonify({"error": "Owner session timed out from inactivity — log in again."}), 401
        g.auth_token = token
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------- public: meta / legal / support

@app.route("/api/health")
def health():
    return jsonify({"ok": True})


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """Product photos, banners, and logos are uploaded to this backend's own disk
    (frontend/static/uploads/) at runtime - GitHub Pages is a static, git-committed
    host and has no way to reflect a file that showed up after deploy, so this
    route (served by wherever the backend actually runs) is how the frontend
    reaches them, not a GitHub Pages URL. Image paths returned by the API (e.g.
    "uploads/xyz.png") resolve as API_BASE + "/" + that path."""
    return send_from_directory(UPLOAD_DIR, filename)


@app.route("/api/meta")
def meta():
    """Everything the frontend needs to render static/config-driven bits without a
    dozen separate calls: cutoff date, plan catalog, customization options."""
    return jsonify({
        "root_domain": ROOT_DOMAIN,
        "demo_video_id": DEMO_VIDEO_ID,
        "site_cutoff": site_cutoff_label(),
        "is_cut_off": site_is_cut_off(),
        "theme_presets": THEME_PRESETS,
        "font_pairings": FONT_PAIRINGS,
        "layout_styles": LAYOUT_STYLES,
        "accent_styles": ACCENT_STYLES,
        "banner_styles": BANNER_STYLES,
        "card_styles": CARD_STYLES,
        "themes": THEMES,
        "page_looks": PAGE_LOOKS,
        "button_styles": BUTTON_STYLES,
        "ship_to_options": SHIP_TO_OPTIONS,
        "plans": {k: plan_to_dict(k) for k in PLAN_ORDER},
        "plan_order": PLAN_ORDER,
        "setup_fee_dollars": SETUP_FEE_DOLLARS,
    })


@app.route("/api/support", methods=["POST"])
def support():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip()
    subject = (data.get("subject") or "").strip()
    message = (data.get("message") or "").strip()
    store_subdomain = (data.get("store_subdomain") or "").strip() or None
    if not email or not message:
        return jsonify({"error": "Add your email and a message so we can help."}), 400
    with get_db() as conn:
        conn.execute(
            "INSERT INTO support_messages (email, subject, message, store_subdomain) VALUES (?, ?, ?, ?)",
            (email, subject, message, store_subdomain),
        )
    return jsonify({"ok": True})


@app.route("/api/leads/service", methods=["POST"])
def lead_service():
    data = request.get_json(force=True, silent=True) or {}
    description = (data.get("description") or "").strip()
    email = (data.get("email") or "").strip()
    if not description or not email:
        return jsonify({"error": "Tell us what you're building and leave an email so we can reply."}), 400
    with get_db() as conn:
        conn.execute("INSERT INTO leads (kind, description, email) VALUES ('service', ?, ?)", (description, email))
    return jsonify({"ok": True})


# ---------------------------------------------------------------- signup

@app.route("/api/subdomain-check", methods=["POST"])
def subdomain_check():
    data = request.get_json(force=True, silent=True) or {}
    raw = (data.get("name") or "").strip().lower()
    cleaned = re.sub(r"[^a-z]", "", raw)
    if not cleaned or not SUBDOMAIN_RE.match(cleaned):
        return jsonify({"cleaned": cleaned, "valid": False, "available": None, "error": "Letters only, please (a–z)."})
    if cleaned in RESERVED_SUBDOMAINS:
        return jsonify({"cleaned": cleaned, "valid": False, "available": None, "error": "That name is reserved — pick another."})
    with get_db() as conn:
        taken = conn.execute("SELECT 1 FROM stores WHERE subdomain=?", (cleaned,)).fetchone()
    return jsonify({"cleaned": cleaned, "valid": True, "available": taken is None})


@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json(force=True, silent=True) or {}
    subdomain = re.sub(r"[^a-z]", "", (data.get("subdomain") or "").strip().lower())
    business_name = (data.get("business_name") or "").strip() or subdomain
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    is_physical = data.get("is_physical")
    agreed = bool(data.get("agree_terms"))

    if not subdomain or not SUBDOMAIN_RE.match(subdomain):
        return jsonify({"error": "Pick a store name first (letters only)."}), 400
    if subdomain in RESERVED_SUBDOMAINS:
        return jsonify({"error": "That name is reserved — pick another."}), 400
    if not email or not password or is_physical not in (True, False):
        return jsonify({"error": "Fill in your email, a password, and whether this ships physical items."}), 400
    if not agreed:
        return jsonify({"error": "You need to agree to the Seller Terms and Privacy Policy to open a store."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password needs to be at least 8 characters."}), 400

    with get_db() as conn:
        taken = conn.execute("SELECT 1 FROM stores WHERE subdomain=?", (subdomain,)).fetchone()
        if taken:
            return jsonify({"error": "That name just got taken — pick another."}), 409

        # A cheap but real guardrail against the obvious version of "just keep
        # making new free stores": cap how many stores one IP can create per day.
        if not security.signup_allowed(conn):
            return jsonify({"error": "Too many stores created from this network today — if you need more than a few, get in touch through Support instead."}), 429

        cur = conn.execute(
            """INSERT INTO stores
               (subdomain, business_name, owner_email, password_hash, is_physical, terms_accepted_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (subdomain, business_name, email, generate_password_hash(password), 1 if is_physical else 0, now_iso()),
        )
        store_id = cur.lastrowid
        token = security.create_session(conn, store_id=store_id, lifetime_hours=12)
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()

    return jsonify({"token": token, "store": store_to_dict(store, include_private=True)})


# ---------------------------------------------------------------- store login

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True) or {}
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    with get_db() as conn:
        if email:
            locked, retry_after = security.is_locked_out(conn, "store", email)
            if locked:
                return jsonify({"error": f"Too many failed attempts. Try again in about {max(1, retry_after // 60)} minute(s)."}), 429
        store = conn.execute("SELECT * FROM stores WHERE owner_email=?", (email,)).fetchone()
        if store and check_password_hash(store["password_hash"], password):
            if store["suspended_at"]:
                # Correct password still doesn't get you in - a suspended account
                # can't be reactivated by logging back in, only by the owner.
                security.log_event(conn, "store", email, "login_blocked_suspended")
                return jsonify({"error": "This account has been suspended." + (f" Reason: {store['suspended_reason']}" if store["suspended_reason"] else " Contact support for details."), "code": "suspended"}), 403
            security.reset_attempts(conn, "store", email)
            security.log_event(conn, "store", email, "login_success")
            token = security.create_session(conn, store_id=store["id"], lifetime_hours=12)
            return jsonify({"token": token, "store": store_to_dict(store, include_private=True)})
        security.record_failed_login(conn, "store", email or "unknown")
        security.log_event(conn, "store", email or "(blank)", "login_failed")
    return jsonify({"error": "No match for that email/password."}), 401


@app.route("/api/logout", methods=["POST"])
@require_store_auth
def logout():
    with get_db() as conn:
        security.delete_session(conn, g.auth_token)
    return jsonify({"ok": True})


@app.route("/api/me")
@require_store_auth
def me():
    return jsonify({"store": store_to_dict(g.store, include_private=True)})


# ---------------------------------------------------------------- owner login

@app.route("/api/auth/owner/login", methods=["POST"])
def owner_login():
    """Password-only on purpose - a username adds no real security here (there's
    only ever one owner account), so dropping the field is pure UX. OWNER_USERNAME
    still exists internally, only as the label attached to audit-log entries."""
    data = request.get_json(force=True, silent=True) or {}
    password = data.get("password") or ""
    with get_db() as conn:
        locked, retry_after = security.is_locked_out(conn, "owner", OWNER_USERNAME)
        if locked:
            return jsonify({"error": f"Too many failed attempts. Try again in about {max(1, retry_after // 60)} minute(s)."}), 429

        valid = bool(OWNER_PASSWORD) and hmac.compare_digest(password, OWNER_PASSWORD)
        if not valid:
            security.record_failed_login(conn, "owner", OWNER_USERNAME)
            security.log_event(conn, "owner", "(attempt)", "login_failed")
            return jsonify({"error": "Nope."}), 401

        if _owner_2fa_enabled():
            pending_token = security.create_session(conn, is_owner=True, owner_2fa_pending=True, lifetime_hours=(5 / 60))
            security.log_event(conn, "owner", OWNER_USERNAME, "login_password_ok_awaiting_2fa")
            return jsonify({"need_code": True, "pending_token": pending_token})

        security.reset_attempts(conn, "owner", OWNER_USERNAME)
        security.log_event(conn, "owner", OWNER_USERNAME, "login_success")
        token = security.create_session(conn, is_owner=True, lifetime_hours=12)
        return jsonify({"token": token})


@app.route("/api/auth/owner/2fa", methods=["POST"])
def owner_2fa():
    data = request.get_json(force=True, silent=True) or {}
    pending_token = data.get("pending_token") or ""
    code = (data.get("code") or "").strip()
    with get_db() as conn:
        sess = security.get_session(conn, pending_token)
        if not sess or not sess["is_owner"] or not sess["owner_2fa_pending"]:
            return jsonify({"error": "That code expired — log in again."}), 401
        locked, retry_after = security.is_locked_out(conn, "owner", OWNER_USERNAME)
        if locked:
            security.delete_session(conn, pending_token)
            return jsonify({"error": f"Too many failed attempts. Try again in about {max(1, retry_after // 60)} minute(s)."}), 429
        if not pyotp or not pyotp.TOTP(OWNER_TOTP_SECRET).verify(code, valid_window=1):
            security.record_failed_login(conn, "owner", OWNER_USERNAME)
            security.log_event(conn, "owner", OWNER_USERNAME, "login_2fa_failed")
            return jsonify({"error": "Wrong code."}), 401
        security.reset_attempts(conn, "owner", OWNER_USERNAME)
        security.log_event(conn, "owner", OWNER_USERNAME, "login_success", "2fa")
        security.upgrade_session_to_owner(conn, sess, lifetime_hours=12)
    return jsonify({"token": pending_token})


@app.route("/api/owner/logout", methods=["POST"])
@require_owner_auth
def owner_logout():
    with get_db() as conn:
        security.delete_session(conn, g.auth_token)
    return jsonify({"ok": True})


# ---------------------------------------------------------------- setup fee via Helcim (platform account)

@app.route("/api/setup-fee")
@require_store_auth
def setup_fee_status():
    return jsonify({"amount_cents": int(SETUP_FEE_DOLLARS * 100), "paid": bool(g.store["setup_paid"])})


@app.route("/api/setup-fee/init", methods=["POST"])
@require_store_auth
def setup_fee_init():
    try:
        checkout_token, secret_token = helcim.initialize_checkout(
            SETUP_FEE_DOLLARS, description=f"Peltier Development setup - store {g.store['id']}"
        )
    except helcim.HelcimError as e:
        return jsonify({"error": str(e)}), 502
    # The Helcim secret token has to survive until /confirm. It can't live on the
    # login session row (api_sessions) - that row is shared across every request
    # for this login, so two in-flight payments (two tabs, a retry) would stomp on
    # each other's token. A one-time, high-entropy reference in its own table
    # avoids that (this is a lookup key for a secret, not a human-facing order
    # code, so it uses real token entropy rather than gen_ref()'s 6 characters).
    with get_db() as conn:
        ref = secrets_mod.token_urlsafe(24)
        conn.execute(
            "INSERT INTO pending_payments (ref, kind, store_id, secret_token, extra) VALUES (?, 'setup_fee', ?, ?, NULL)",
            (ref, g.store["id"], secret_token),
        )
    return jsonify({"checkoutToken": checkout_token, "paymentRef": ref})


@app.route("/api/setup-fee/confirm", methods=["POST"])
@require_store_auth
def setup_fee_confirm():
    """Never trust the browser's SUCCESS message alone - re-verify with Helcim
    server-side before marking anything paid, and confirm the transaction is
    actually for THIS store's amount and pending-payment record before it counts."""
    data = request.get_json(force=True, silent=True) or {}
    transaction_id = data.get("transactionId")
    payment_ref = data.get("paymentRef")
    if not transaction_id or not payment_ref:
        return jsonify({"ok": False, "error": "Missing transaction/payment reference"}), 400
    with get_db() as conn:
        pending = conn.execute(
            "SELECT * FROM pending_payments WHERE ref=? AND kind='setup_fee' AND store_id=?",
            (payment_ref, g.store["id"]),
        ).fetchone()
        if not pending:
            return jsonify({"ok": False, "error": "Payment reference mismatch — start over."}), 400
        try:
            result = helcim.verify_transaction(transaction_id, pending["secret_token"])
        except helcim.HelcimError as e:
            return jsonify({"ok": False, "error": str(e)}), 502

        approved = str(result.get("status", "")).lower() in ("approved", "success", "purchase")
        amount_ok = abs(float(result.get("amount", 0)) - SETUP_FEE_DOLLARS) < 0.01
        if not approved or not amount_ok:
            return jsonify({"ok": False, "error": "Transaction not approved or amount mismatch"}), 402

        conn.execute(
            "UPDATE stores SET setup_paid=1, setup_helcim_transaction_id=? WHERE id=?",
            (str(transaction_id), g.store["id"]),
        )
        conn.execute("DELETE FROM pending_payments WHERE ref=?", (payment_ref,))
    return jsonify({"ok": True})


# ---------------------------------------------------------------- admin: dashboard

@app.route("/api/dashboard")
@require_store_auth
@require_paid
def dashboard():
    with get_db() as conn:
        product_count = conn.execute("SELECT COUNT(*) c FROM products WHERE store_id=?", (g.store["id"],)).fetchone()["c"]
        orders = conn.execute(
            "SELECT * FROM orders WHERE store_id=? ORDER BY created_at DESC LIMIT 5", (g.store["id"],)
        ).fetchall()
        revenue = conn.execute(
            "SELECT COALESCE(SUM(total_cents),0) t FROM orders WHERE store_id=? AND paid=1", (g.store["id"],)
        ).fetchone()["t"]
        pending_orders = conn.execute(
            "SELECT COUNT(*) c FROM orders WHERE store_id=? AND paid=1 AND status='paid'", (g.store["id"],)
        ).fetchone()["c"]
        payment_settings = conn.execute(
            "SELECT 1 FROM store_payment_settings WHERE store_id=? AND helcim_account_id IS NOT NULL", (g.store["id"],)
        ).fetchone()
        ok, plan_key, used, cap = plan_room_check(conn, g.store)
    return jsonify({
        "product_count": product_count,
        "recent_orders": [order_to_dict(o, include_shipping=True) for o in orders],
        "revenue_cents": revenue,
        "pending_orders": pending_orders,
        "site_cutoff": site_cutoff_label(),
        "is_cut_off": site_is_cut_off(),
        "payment_connected": bool(payment_settings),
        "plan": plan_to_dict(plan_key),
        "used_cents": used,
        "cap_cents": cap,
        "near_cap": cap is not None and used >= cap * 0.9,
    })


# ---------------------------------------------------------------- admin: products

@app.route("/api/products", methods=["GET", "POST"])
@require_store_auth
@require_paid
def products():
    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        description = (request.form.get("description") or "").strip()
        price = (request.form.get("price") or "0").strip()
        try:
            price_cents = int(round(float(price) * 100))
        except ValueError:
            price_cents = 0

        image_path = None
        file = request.files.get("image")
        if file and file.filename:
            if not security.validate_image_upload(file):
                return jsonify({"error": "That image file couldn't be verified — try a plain PNG/JPG/GIF/WEBP."}), 400
            ext = file.filename.rsplit(".", 1)[-1].lower()
            base_name = security.safe_upload_name("s{}_product".format(g.store["id"]))
            fname = secure_filename(f"{base_name}.{ext}")
            file.save(os.path.join(UPLOAD_DIR, fname))
            image_path = f"uploads/{fname}"

        if not (name and price_cents > 0):
            return jsonify({"error": "Give it a name and a price above $0."}), 400

        with get_db() as conn:
            conn.execute(
                "INSERT INTO products (store_id, name, description, price_cents, image_path) VALUES (?, ?, ?, ?, ?)",
                (g.store["id"], name, description, price_cents, image_path),
            )

    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM products WHERE store_id=? ORDER BY created_at DESC", (g.store["id"],)
        ).fetchall()
    return jsonify({"products": [product_to_dict(p) for p in rows]})


@app.route("/api/products/<int:product_id>/toggle", methods=["POST"])
@require_store_auth
@require_paid
def toggle_product(product_id):
    with get_db() as conn:
        conn.execute("UPDATE products SET active = 1 - active WHERE id=? AND store_id=?", (product_id, g.store["id"]))
    return jsonify({"ok": True})


# ---------------------------------------------------------------- admin: orders

@app.route("/api/orders")
@require_store_auth
@require_paid
def orders():
    """Shipping/contact info only ever reaches the response for orders that are
    actually paid - see order_to_dict, which checks o['paid'] before including
    anything from shipping_address/customer_name/customer_email."""
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM orders WHERE store_id=? ORDER BY created_at DESC", (g.store["id"],)).fetchall()
    return jsonify({"orders": [order_to_dict(o, include_shipping=True) for o in rows]})


@app.route("/api/orders/<int:order_id>/confirm", methods=["POST"])
@require_store_auth
@require_paid
def confirm_order(order_id):
    data = request.get_json(force=True, silent=True) or {}
    with get_db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=? AND store_id=?", (order_id, g.store["id"])).fetchone()
        if not order or not order["paid"]:
            return jsonify({"error": "That order hasn't shown as paid yet — nothing to confirm."}), 400

        if order["status"] == "paid":
            conn.execute("UPDATE orders SET status='confirmed' WHERE id=?", (order_id,))
            security.log_event(conn, "store", g.store["owner_email"], "order_confirmed", f"order #{order_id}")
            new_status = "confirmed"
        elif order["status"] == "confirmed":
            tracking = (data.get("tracking_number") or "").strip()
            carrier = (data.get("tracking_carrier") or "").strip()
            conn.execute(
                "UPDATE orders SET status='shipped', tracking_number=?, tracking_carrier=? WHERE id=?",
                (tracking or None, carrier or None, order_id),
            )
            security.log_event(conn, "store", g.store["owner_email"], "order_shipped", f"order #{order_id}")
            new_status = "shipped"
        else:
            new_status = order["status"]
        updated = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    return jsonify({"ok": True, "order": order_to_dict(updated, include_shipping=True), "status": new_status})


@app.route("/api/orders/<int:order_id>/mark-paid", methods=["POST"])
@require_store_auth
@require_paid
def mark_order_paid(order_id):
    """Manual confirmation for e-transfer orders - the seller checks their own
    bank, sees the deposit (ideally matching the reference code shown at
    checkout), and clicks this. email_watcher.py can do this same update
    automatically later if IMAP access is set up - this is the zero-setup
    version that works tonight with no extra config."""
    with get_db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=? AND store_id=?", (order_id, g.store["id"])).fetchone()
        if not order:
            return jsonify({"error": "Order not found."}), 404
        if order["payment_method"] not in ("etransfer", "paypal"):
            return jsonify({"error": "This order isn't an e-transfer or PayPal order."}), 400
        if order["paid"]:
            return jsonify({"ok": True})  # idempotent
        conn.execute("UPDATE orders SET paid=1, status='paid' WHERE id=?", (order_id,))
        security.log_event(conn, "store", g.store["owner_email"], "order_marked_paid_manually", f"order #{order_id}")
        updated = conn.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
    return jsonify({"ok": True, "order": order_to_dict(updated, include_shipping=True)})


# ---------------------------------------------------------------- admin: payment settings

PAYPAL_ME_RE = re.compile(r"^[A-Za-z0-9]{1,20}$")


def _payment_state(conn, store_id):
    settings = conn.execute("SELECT * FROM store_payment_settings WHERE store_id=?", (store_id,)).fetchone()
    s = conn.execute("SELECT etransfer_email, paypal_me, paypal_email, etransfer_discount_pct FROM stores WHERE id=?", (store_id,)).fetchone()
    return {
        "connected": bool((settings and settings["helcim_account_id"]) or s["etransfer_email"] or s["paypal_me"]),
        "helcim_account_id": settings["helcim_account_id"] if settings else None,
        "etransfer_email": s["etransfer_email"],
        "paypal_me": s["paypal_me"],
        "paypal_email": s["paypal_email"],
        "etransfer_discount_pct": s["etransfer_discount_pct"] or 0,
        # neither the Helcim API token nor any bank/mail credential is ever sent back out
    }


@app.route("/api/payment-settings", methods=["GET", "POST"])
@require_store_auth
@require_paid
def payment_settings():
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        if "enable_etransfer" not in data and data.get("etransfer_email"):
            data["enable_etransfer"] = True     # older single-field form
        updates = {}

        if "enable_paypal" in data:
            if data["enable_paypal"]:
                name = (data.get("paypal_me") or "").strip()
                name = re.sub(r"^(https?://)?(www\.)?paypal\.me/", "", name, flags=re.I).strip("/ ").split("/")[0]
                if not PAYPAL_ME_RE.match(name):
                    return jsonify({"error": "Enter your PayPal.me name (letters and numbers only, e.g. yourshop)."}), 400
                pe = (data.get("paypal_email") or "").strip().lower()
                if pe and "@" not in pe:
                    return jsonify({"error": "That PayPal email doesn't look right."}), 400
                updates["paypal_me"], updates["paypal_email"] = name, (pe or None)
            else:
                updates["paypal_me"], updates["paypal_email"] = None, None

        if "enable_etransfer" in data:
            if data["enable_etransfer"]:
                e = (data.get("etransfer_email") or "").strip().lower()
                if "@" not in e:
                    return jsonify({"error": "Enter the email address your bank uses for e-Transfer Autodeposit."}), 400
                updates["etransfer_email"] = e
            else:
                updates["etransfer_email"] = None

        if "etransfer_discount_pct" in data:
            try:
                pct = int(data["etransfer_discount_pct"])
            except (TypeError, ValueError):
                pct = 0
            updates["etransfer_discount_pct"] = max(0, min(pct, 10))

        account_id = (data.get("helcim_account_id") or "").strip()
        api_token = (data.get("helcim_api_token") or "").strip()

        if not updates and not (account_id and api_token):
            return jsonify({"error": "Nothing to save."}), 400

        with get_db() as conn:
            if updates:
                cols = ", ".join(f"{k}=?" for k in updates)      # keys are the fixed names above
                conn.execute(f"UPDATE stores SET {cols} WHERE id=?", (*updates.values(), g.store["id"]))
                security.log_event(conn, "store", g.store["owner_email"], "payment_methods_updated", ",".join(updates))
            if account_id and api_token:
                conn.execute(
                    """INSERT INTO store_payment_settings (store_id, helcim_account_id, helcim_api_token_encrypted)
                       VALUES (?, ?, ?)
                       ON CONFLICT(store_id) DO UPDATE SET
                         helcim_account_id=excluded.helcim_account_id,
                         helcim_api_token_encrypted=excluded.helcim_api_token_encrypted,
                         updated_at=CURRENT_TIMESTAMP""",
                    (g.store["id"], account_id, crypto_utils.encrypt(api_token)),
                )
                security.log_event(conn, "store", g.store["owner_email"], "payment_settings_updated")

    with get_db() as conn:
        state = _payment_state(conn, g.store["id"])
    state["auto_verify"] = _auto_verify_enabled(g.store["id"])
    return jsonify(state)


# ---------------------------------------------------------------- admin: customize

@app.route("/api/customize", methods=["GET", "POST"])
@require_store_auth
@require_paid
def customize():
    if request.method == "POST":
        theme_color = (request.form.get("theme_color") or "").strip()
        custom_color = (request.form.get("custom_color") or "").strip()
        # A custom swatch wins over a preset only if it's a genuine 6-digit hex -
        # otherwise silently fall back rather than saving a broken --accent value.
        if custom_color and HEX_COLOR_RE.match(custom_color):
            theme_color = custom_color
        valid_presets = {t["hex"] for t in THEME_PRESETS}
        if theme_color not in valid_presets and not HEX_COLOR_RE.match(theme_color):
            theme_color = g.store["theme_color"]

        tagline = (request.form.get("tagline") or "").strip()[:120]
        about_text = (request.form.get("about_text") or "").strip()[:600]
        font_choice = (request.form.get("font_choice") or "").strip()
        if font_choice not in FONT_PAIRINGS:
            font_choice = g.store["font_choice"] or "signature"
        layout_style = (request.form.get("layout_style") or "").strip()
        if layout_style not in {s["key"] for s in LAYOUT_STYLES}:
            layout_style = g.store["layout_style"] or "grid"
        accent_style = (request.form.get("accent_style") or "").strip()
        if accent_style not in {s["key"] for s in ACCENT_STYLES}:
            accent_style = g.store["accent_style"] or "rounded"
        banner_style = (request.form.get("banner_style") or "").strip()
        if banner_style not in {s["key"] for s in BANNER_STYLES}:
            banner_style = g.store["banner_style"] or "image"
        card_style = (request.form.get("card_style") or "").strip()
        if card_style not in {s["key"] for s in CARD_STYLES}:
            card_style = g.store["card_style"] or "shadow"
        page_look = (request.form.get("page_look") or "").strip()
        if page_look not in {s["key"] for s in PAGE_LOOKS}:
            page_look = g.store["page_look"] or "dark"
        button_style = (request.form.get("button_style") or "").strip()
        if button_style not in {s["key"] for s in BUTTON_STYLES}:
            button_style = g.store["button_style"] or "solid"

        announcement = (request.form.get("announcement") or "").strip()[:140]
        order_button_text = (request.form.get("order_button_text") or "").strip()[:24]
        footer_note = (request.form.get("footer_note") or "").strip()[:300]
        try:
            grid_columns = int(request.form.get("grid_columns") or g.store["grid_columns"] or 2)
        except (TypeError, ValueError):
            grid_columns = 2
        if grid_columns not in (2, 3, 4):
            grid_columns = 2
        hero_align = (request.form.get("hero_align") or "").strip()
        if hero_align not in ("left", "center"):
            hero_align = g.store["hero_align"] or "left"

        ships_to = (request.form.get("ships_to") or "").strip()
        if ships_to not in SHIP_TO_COUNTRIES:
            ships_to = g.store["ships_to"] or "ca"
        try:
            shipping_flat_cents = max(0, int(round(float(request.form.get("shipping_flat_dollars", "0") or "0") * 100)))
        except (TypeError, ValueError):
            shipping_flat_cents = g.store["shipping_flat_cents"] or 0

        social_instagram = (request.form.get("social_instagram") or "").strip()[:100]
        social_website = (request.form.get("social_website") or "").strip()[:200]
        if social_website and not re.match(r"^https?://", social_website, re.I):
            social_website = "https://" + social_website

        banner_path = g.store["banner_image"]
        file = request.files.get("banner")
        if file and file.filename:
            if not security.validate_image_upload(file):
                return jsonify({"error": "Banner image couldn't be verified — try a plain PNG/JPG/GIF/WEBP."}), 400
            ext = file.filename.rsplit(".", 1)[-1].lower()
            fname = secure_filename(f"{security.safe_upload_name('banner_s' + str(g.store['id']))}.{ext}")
            file.save(os.path.join(UPLOAD_DIR, fname))
            banner_path = f"uploads/{fname}"

        logo_path = g.store["logo_image"]
        logo_file = request.files.get("logo")
        if logo_file and logo_file.filename:
            if not security.validate_image_upload(logo_file):
                return jsonify({"error": "Logo image couldn't be verified — try a plain PNG/JPG/GIF/WEBP."}), 400
            ext = logo_file.filename.rsplit(".", 1)[-1].lower()
            fname = secure_filename(f"{security.safe_upload_name('logo_s' + str(g.store['id']))}.{ext}")
            logo_file.save(os.path.join(UPLOAD_DIR, fname))
            logo_path = f"uploads/{fname}"

        with get_db() as conn:
            conn.execute(
                """UPDATE stores SET theme_color=?, about_text=?, banner_image=?, tagline=?, logo_image=?,
                   font_choice=?, layout_style=?, accent_style=?, banner_style=?, card_style=?, page_look=?, button_style=?,
                   announcement=?, order_button_text=?, grid_columns=?, hero_align=?, footer_note=?,
                   ships_to=?, shipping_flat_cents=?,
                   social_instagram=?, social_website=?
                   WHERE id=?""",
                (theme_color, about_text, banner_path, tagline, logo_path,
                 font_choice, layout_style, accent_style, banner_style, card_style, page_look, button_style,
                 announcement or None, order_button_text or None, grid_columns, hero_align, footer_note or None,
                 ships_to, shipping_flat_cents,
                 social_instagram, social_website or None,
                 g.store["id"]),
            )
            store = conn.execute("SELECT * FROM stores WHERE id=?", (g.store["id"],)).fetchone()
        return jsonify({"ok": True, "store": store_to_dict(store, include_private=True)})

    return jsonify({"store": store_to_dict(g.store, include_private=True)})


# ---------------------------------------------------------------- admin: plan / revenue cap

@app.route("/api/plan")
@require_store_auth
@require_paid
def plan_status():
    with get_db() as conn:
        ok, plan_key, used, cap = plan_room_check(conn, g.store)
        open_invoice = _current_open_invoice(conn, g.store)
        accrued_credit_cents = growth_fee_credit_cents(conn, g.store) if plan_key == "growth" else 0
    overdue = None
    if open_invoice:
        due_by = date.fromisoformat(open_invoice["period_end"]) + timedelta(days=GRACE_DAYS)
        overdue = date.today() > due_by
    return jsonify({
        "current_plan": plan_to_dict(plan_key),
        "used_cents": used,
        "cap_cents": cap,
        "renews_at": g.store["plan_renews_at"],
        "accrued_credit_cents": accrued_credit_cents,
        "open_invoice": ({
            "id": open_invoice["id"], "period_start": open_invoice["period_start"],
            "period_end": open_invoice["period_end"], "amount_cents": open_invoice["amount_cents"],
            "overdue": overdue,
        } if open_invoice else None),
        "grace_days": GRACE_DAYS,
    })


@app.route("/api/plan/upgrade/<plan_key>")
@require_store_auth
@require_paid
def plan_upgrade_preview(plan_key):
    if plan_key not in PLAN_ORDER or plan_key == "starter":
        abort(404)
    plan = PLANS[plan_key]
    with get_db() as conn:
        credit_cents = growth_fee_credit_cents(conn, g.store) if plan_key == "growth" else 0
    full_price_cents = int(plan["price_dollars"] * 100)
    charge_cents = max(full_price_cents - credit_cents, 0)
    return jsonify({
        "plan": plan_to_dict(plan_key),
        "full_price_cents": full_price_cents,
        "credit_cents": credit_cents,
        "charge_cents": charge_cents,
    })


@app.route("/api/plan/upgrade/<plan_key>/init", methods=["POST"])
@require_store_auth
@require_paid
def plan_upgrade_init(plan_key):
    if plan_key not in PLAN_ORDER or plan_key == "starter":
        return jsonify({"error": "Not a valid plan."}), 400
    plan = PLANS[plan_key]
    # Recomputed server-side, never trusted from the client - the amount actually
    # charged is whatever this comes out to right now.
    with get_db() as conn:
        credit_cents = growth_fee_credit_cents(conn, g.store) if plan_key == "growth" else 0
    charge_cents = max(int(plan["price_dollars"] * 100) - credit_cents, 0)
    try:
        checkout_token, secret_token = helcim.initialize_checkout(
            charge_cents / 100, description=f"Peltier Development {plan['label']} plan - store {g.store['id']}"
        )
    except helcim.HelcimError as e:
        return jsonify({"error": str(e)}), 502
    with get_db() as conn:
        ref = secrets_mod.token_urlsafe(24)
        conn.execute(
            "INSERT INTO pending_payments (ref, kind, store_id, secret_token, extra) VALUES (?, 'plan_upgrade', ?, ?, ?)",
            (ref, g.store["id"], secret_token, json.dumps({"plan_key": plan_key, "charge_cents": charge_cents})),
        )
    return jsonify({"checkoutToken": checkout_token, "paymentRef": ref})


@app.route("/api/plan/upgrade/<plan_key>/confirm", methods=["POST"])
@require_store_auth
@require_paid
def plan_upgrade_confirm(plan_key):
    """Same never-trust-the-browser pattern as setup-fee/confirm: re-verify with
    Helcim server-side, charged to the PLATFORM's own account, before the plan
    changes."""
    data = request.get_json(force=True, silent=True) or {}
    transaction_id = data.get("transactionId")
    payment_ref = data.get("paymentRef")
    if not transaction_id or not payment_ref:
        return jsonify({"ok": False, "error": "Missing transaction/payment reference"}), 400

    with get_db() as conn:
        pending = conn.execute(
            "SELECT * FROM pending_payments WHERE ref=? AND kind='plan_upgrade' AND store_id=?",
            (payment_ref, g.store["id"]),
        ).fetchone()
        if not pending:
            return jsonify({"ok": False, "error": "Payment reference mismatch — start the upgrade again."}), 400
        extra = json.loads(pending["extra"])
        if extra["plan_key"] != plan_key:
            return jsonify({"ok": False, "error": "Plan mismatch — start the upgrade again."}), 400
        charge_cents = extra["charge_cents"]
        plan = PLANS[plan_key]

        try:
            result = helcim.verify_transaction(transaction_id, pending["secret_token"])
        except helcim.HelcimError as e:
            return jsonify({"ok": False, "error": str(e)}), 502

        approved = str(result.get("status", "")).lower() in ("approved", "success", "purchase")
        amount_ok = abs(float(result.get("amount", 0)) - charge_cents / 100) < 0.01
        if not approved or not amount_ok:
            return jsonify({"ok": False, "error": "Transaction not approved or amount mismatch"}), 402

        now = datetime.now(timezone.utc)
        # Switching plans resets plan_started_at (Scale's monthly invoices are
        # anchored to it) - but re-paying the *same* plan you're already on doesn't,
        # so an existing Scale invoice history keeps lining up correctly.
        row = conn.execute("SELECT plan, plan_started_at FROM stores WHERE id=?", (g.store["id"],)).fetchone()
        plan_started = row["plan_started_at"] if row["plan"] == plan_key and row["plan_started_at"] else now.isoformat()
        renews_at = (now + timedelta(days=PLAN_PERIOD_DAYS)).isoformat() if plan["kind"] == "flat" else None
        conn.execute(
            "UPDATE stores SET plan=?, plan_started_at=?, plan_renews_at=? WHERE id=?",
            (plan_key, plan_started, renews_at, g.store["id"]),
        )
        conn.execute(
            "INSERT INTO plan_payments (store_id, plan, amount_cents, helcim_transaction_id) VALUES (?, ?, ?, ?)",
            (g.store["id"], plan_key, charge_cents, str(transaction_id)),
        )
        security.log_event(conn, "store", g.store["owner_email"], "plan_upgraded", f"{plan_key} - charged {money(charge_cents)}")
        conn.execute("DELETE FROM pending_payments WHERE ref=?", (payment_ref,))
    return jsonify({"ok": True})


@app.route("/api/plan/invoice/pay/init", methods=["POST"])
@require_store_auth
@require_paid
def plan_invoice_pay_init():
    with get_db() as conn:
        get_or_create_scale_invoice(conn, g.store)  # make sure this month's bill exists if it should
        invoice = _current_open_invoice(conn, g.store)
    if not invoice:
        return jsonify({"error": "Nothing owing right now."}), 400
    try:
        checkout_token, secret_token = helcim.initialize_checkout(
            invoice["amount_cents"] / 100, description=f"Peltier Development Scale invoice #{invoice['id']} - store {g.store['id']}"
        )
    except helcim.HelcimError as e:
        return jsonify({"error": str(e)}), 502
    with get_db() as conn:
        ref = secrets_mod.token_urlsafe(24)
        conn.execute(
            "INSERT INTO pending_payments (ref, kind, store_id, secret_token, extra) VALUES (?, 'plan_invoice', ?, ?, ?)",
            (ref, g.store["id"], secret_token, json.dumps({"invoice_id": invoice["id"]})),
        )
    return jsonify({"checkoutToken": checkout_token, "paymentRef": ref, "amount_cents": invoice["amount_cents"]})


@app.route("/api/plan/invoice/pay/confirm", methods=["POST"])
@require_store_auth
@require_paid
def plan_invoice_pay_confirm():
    data = request.get_json(force=True, silent=True) or {}
    transaction_id = data.get("transactionId")
    payment_ref = data.get("paymentRef")
    if not transaction_id or not payment_ref:
        return jsonify({"ok": False, "error": "Missing transaction/payment reference"}), 400

    with get_db() as conn:
        pending = conn.execute(
            "SELECT * FROM pending_payments WHERE ref=? AND kind='plan_invoice' AND store_id=?",
            (payment_ref, g.store["id"]),
        ).fetchone()
        if not pending:
            return jsonify({"ok": False, "error": "Payment reference mismatch — refresh and try again."}), 400
        invoice_id = json.loads(pending["extra"])["invoice_id"]
        invoice = conn.execute(
            "SELECT * FROM plan_invoices WHERE id=? AND store_id=?", (invoice_id, g.store["id"])
        ).fetchone()
        if not invoice or invoice["paid"]:
            return jsonify({"ok": False, "error": "Invoice mismatch — refresh and try again."}), 400

        try:
            result = helcim.verify_transaction(transaction_id, pending["secret_token"])
        except helcim.HelcimError as e:
            return jsonify({"ok": False, "error": str(e)}), 502

        approved = str(result.get("status", "")).lower() in ("approved", "success", "purchase")
        amount_ok = abs(float(result.get("amount", 0)) - invoice["amount_cents"] / 100) < 0.01
        if not approved or not amount_ok:
            return jsonify({"ok": False, "error": "Transaction not approved or amount mismatch"}), 402

        conn.execute(
            "UPDATE plan_invoices SET paid=1, paid_at=?, helcim_transaction_id=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), str(transaction_id), invoice_id),
        )
        conn.execute(
            "INSERT INTO plan_payments (store_id, plan, amount_cents, helcim_transaction_id) VALUES (?, 'scale', ?, ?)",
            (g.store["id"], invoice["amount_cents"], str(transaction_id)),
        )
        security.log_event(conn, "store", g.store["owner_email"], "scale_invoice_paid", f"invoice #{invoice_id}")
        conn.execute("DELETE FROM pending_payments WHERE ref=?", (payment_ref,))
    return jsonify({"ok": True})


# ---------------------------------------------------------------- public storefronts

def _get_store_row(subdomain):
    with get_db() as conn:
        return conn.execute("SELECT * FROM stores WHERE subdomain=?", (subdomain,)).fetchone()


def _get_store_or_404(subdomain):
    store = _get_store_row(subdomain)
    if not store or not store["setup_paid"]:
        abort(404)
    return store


@app.route("/api/stores/<subdomain>")
def store_public(subdomain):
    store = _get_store_row(subdomain)
    if not store or not store["setup_paid"]:
        abort(404)
    if site_is_cut_off():
        return jsonify({"closed": True, "store": {"business_name": store["business_name"]}})
    if store["suspended_at"]:
        # Deliberately vague to a buyer - the specific reason is between the
        # platform owner and the seller, not broadcast on the storefront.
        return jsonify({"closed": True, "store": {"business_name": store["business_name"]}})
    with get_db() as conn:
        products = conn.execute(
            "SELECT * FROM products WHERE store_id=? AND active=1 ORDER BY created_at DESC", (store["id"],)
        ).fetchall()
        helcim_connected = "helcim" in _store_methods(store, conn)
    store_dict = store_to_dict(store)
    store_dict["helcim_connected"] = helcim_connected
    return jsonify({
        "closed": False,
        "store": store_dict,
        "products": [product_to_dict(p) for p in products],
        "root_domain": ROOT_DOMAIN,
    })


@app.route("/api/stores/<subdomain>/checkout", methods=["POST"])
def store_checkout(subdomain):
    store = _get_store_or_404(subdomain)
    if site_is_cut_off() or store["suspended_at"]:
        return jsonify({"error": "This storefront is closed.", "code": "store_closed"}), 410

    data = request.get_json(force=True, silent=True) or {}
    with get_db() as conn:
        products = {p["id"]: p for p in conn.execute(
            "SELECT * FROM products WHERE store_id=? AND active=1", (store["id"],)
        ).fetchall()}

    customer_name = (data.get("customer_name") or "").strip()
    customer_email = (data.get("customer_email") or "").strip()
    agreed = bool(data.get("agree_terms"))

    # Structured shipping fields rather than one free-text blob - lets us
    # actually validate a postal code and check the buyer's country against
    # what this store ships to, before an order ever gets placed. The single
    # formatted shipping_address string still gets stored (everywhere else in
    # the app - admin orders, the owner portal - displays that one string), it
    # just gets composed here, server-side, from pieces that were each checked.
    ship = data.get("shipping") or {}
    shipping_name = (ship.get("name") or "").strip()[:120]
    shipping_street = (ship.get("street") or "").strip()[:200]
    shipping_unit = (ship.get("unit") or "").strip()[:60]
    shipping_city = (ship.get("city") or "").strip()[:100]
    shipping_province = (ship.get("province") or "").strip()[:100]
    shipping_postal_code = (ship.get("postal_code") or "").strip().upper()
    shipping_country = (ship.get("country") or "").strip().upper()[:2]

    qtys = {}
    for item in data.get("items") or []:
        try:
            pid = int(item.get("product_id"))
            q = int(item.get("qty"))
        except (TypeError, ValueError):
            continue
        if q > 0 and pid in products:
            qtys[pid] = q

    if not qtys:
        return jsonify({"error": "Add at least one item."}), 400

    if store["is_physical"]:
        missing = [label for label, val in [
            ("name", shipping_name), ("street address", shipping_street), ("city", shipping_city),
            ("province/state", shipping_province), ("postal/ZIP code", shipping_postal_code), ("country", shipping_country),
        ] if not val]
        if missing:
            return jsonify({"error": f"Shipping {', '.join(missing)} is required."}), 400

        allowed_countries = SHIP_TO_COUNTRIES.get(store["ships_to"] or "ca", ["CA"])
        if allowed_countries is not None and shipping_country not in allowed_countries:
            allowed_label = next((o["label"] for o in SHIP_TO_OPTIONS if o["key"] == (store["ships_to"] or "ca")), "a supported country")
            return jsonify({"error": f"This store only ships to {allowed_label}.", "code": "shipping_country_unsupported"}), 400

        postal_re = POSTAL_CODE_RE.get(shipping_country)
        if postal_re and not postal_re.match(shipping_postal_code):
            return jsonify({"error": f"That doesn't look like a valid {shipping_country} postal/ZIP code."}), 400

        shipping_address = "\n".join(filter(None, [
            shipping_name,
            shipping_street + (f", {shipping_unit}" if shipping_unit else ""),
            f"{shipping_city}, {shipping_province} {shipping_postal_code}",
            shipping_country,
        ]))
    else:
        shipping_address = None
        shipping_country = None

    if not customer_email:
        return jsonify({"error": "An email is needed so the seller can reach you about your order."}), 400
    if not agreed:
        return jsonify({"error": "You need to agree to the Buyer Terms to place an order."}), 400

    with get_db() as conn:
        offers = _store_methods(store, conn)
    method = (data.get("payment_method") or "").strip()
    if method not in offers:
        if len(offers) == 1:
            method = offers[0]
        elif len(offers) > 1:
            return jsonify({"error": "Choose how you'd like to pay."}), 400
        else:
            method = "helcim"

    # Server computes the total from the DB's own prices - a tampered client-side
    # price never reaches this far, since qty is all we read from the request.
    items = []
    total = 0
    for pid, q in qtys.items():
        p = products[pid]
        items.append({"product_id": pid, "name": p["name"], "qty": q, "price_cents": p["price_cents"]})
        total += p["price_cents"] * q

    # Shipping is a flat rate set by the seller, added server-side - never read
    # from the client, same principle as item prices. Frozen onto the order as
    # shipping_cents so a later rate change doesn't retroactively change what an
    # existing order's total was supposed to be.
    shipping_cents = (store["shipping_flat_cents"] or 0) if store["is_physical"] else 0
    total += shipping_cents

    # Optional seller-set discount for the free method when both are offered.
    pct = store["etransfer_discount_pct"] or 0
    if method == "etransfer" and pct and "paypal" in offers:
        total = int(round(total * (100 - pct) / 100))

    with get_db() as conn:
        ok, plan_key, used, cap = plan_room_check(conn, store, additional_cents=total)
        if not ok:
            return jsonify({
                "error": "This shop has reached its plan's sales limit for this month.",
                "code": "plan_limit", "plan": plan_to_dict(plan_key),
                "used_cents": used, "cap_cents": cap,
            }), 402

        expected = ref = None
        if method in ("etransfer", "paypal"):
            expected = _unique_expected_cents(conn, store["id"], total)
            ref = gen_ref("ORD")

        cur = conn.execute(
            """INSERT INTO orders
               (store_id, customer_name, customer_email, items_json, total_cents,
                needs_shipping, shipping_address, shipping_cents, shipping_country,
                terms_accepted_at, payment_method, payment_ref, etransfer_amount_cents)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (store["id"], customer_name, customer_email, json.dumps(items), total,
             1 if store["is_physical"] else 0, shipping_address or None, shipping_cents, shipping_country,
             now_iso(), method, ref, expected),
        )
        order_id = cur.lastrowid

    resp = {"order_id": order_id, "payment_method": method}
    if method in ("etransfer", "paypal"):
        resp.update({"payment_ref": ref, "amount_cents": expected})
        if method == "etransfer":
            resp["etransfer_email"] = store["etransfer_email"]
        else:
            resp["paypal_link"] = paypal_link(store["paypal_me"], expected)
    return jsonify(resp)


def _get_order_or_404(subdomain, order_id):
    """Every order lookup is scoped to id AND store_id together - an order id alone
    is never enough to touch a row, so one store can never reach into another's."""
    store = _get_store_or_404(subdomain)
    with get_db() as conn:
        order = conn.execute("SELECT * FROM orders WHERE id=? AND store_id=?", (order_id, store["id"])).fetchone()
    if not order:
        abort(404)
    return store, order


@app.route("/api/stores/<subdomain>/orders/<int:order_id>")
def order_status(subdomain, order_id):
    store, order = _get_order_or_404(subdomain, order_id)
    settings = get_store_payment_settings(store["id"])
    d = {
        "store": store_to_dict(store),
        "order": order_to_dict(order, include_shipping=True),
        "payment_connected": bool((settings and settings["helcim_account_id"]) or store["etransfer_email"] or store["paypal_me"]),
        "auto_verify": _auto_verify_enabled(store["id"]),
    }
    if order["payment_method"] == "paypal" and store["paypal_me"]:
        d["paypal_link"] = paypal_link(store["paypal_me"], order["etransfer_amount_cents"] or order["total_cents"])
    return jsonify(d)


@app.route("/api/stores/<subdomain>/orders/<int:order_id>/pay/init", methods=["POST"])
def order_pay_init(subdomain, order_id):
    store, order = _get_order_or_404(subdomain, order_id)
    if order["paid"]:
        return jsonify({"error": "Already paid."}), 400
    if order["payment_method"] == "etransfer":
        return jsonify({"error": "This order pays by e-transfer, not Helcim.", "code": "wrong_payment_method"}), 400
    settings = get_store_payment_settings(store["id"])
    if not settings or not settings["helcim_account_id"]:
        return jsonify({"error": "This store hasn't finished payment setup."}), 400
    # Last gate before real money moves into the seller's own Helcim account - the
    # softer check in checkout can be raced (two customers checking out at once, or
    # time passing between order creation and payment), so re-check here right
    # before a checkout token is even created.
    with get_db() as conn:
        ok, plan_key, used, cap = plan_room_check(conn, store, additional_cents=order["total_cents"])
    if not ok:
        return jsonify({"error": "This shop has reached its plan's sales limit for this month. Ask the seller to upgrade their plan.", "code": "plan_limit"}), 402
    seller_token = crypto_utils.decrypt(settings["helcim_api_token_encrypted"])
    try:
        checkout_token, secret_token = helcim.initialize_checkout(
            order["total_cents"] / 100, api_token=seller_token, description=f"Order {order_id}"
        )
    except helcim.HelcimError as e:
        return jsonify({"error": str(e)}), 502
    with get_db() as conn:
        ref = secrets_mod.token_urlsafe(24)
        conn.execute(
            "INSERT INTO pending_payments (ref, kind, store_id, order_id, secret_token) VALUES (?, 'order', ?, ?, ?)",
            (ref, store["id"], order_id, secret_token),
        )
    return jsonify({"checkoutToken": checkout_token, "paymentRef": ref})


@app.route("/api/stores/<subdomain>/orders/<int:order_id>/pay/confirm", methods=["POST"])
def order_pay_confirm(subdomain, order_id):
    """The gate described in the spec: nothing here marks an order paid, decrements
    stock, or exposes shipping info based on what the browser claims. It's marked
    paid only after Helcim's own API confirms the transaction id, amount, and
    currency line up with THIS order, charged through THIS store's own account."""
    store, order = _get_order_or_404(subdomain, order_id)
    if order["paid"]:
        return jsonify({"ok": True})  # idempotent - a retried/duplicate confirm is a no-op
    settings = get_store_payment_settings(store["id"])
    seller_token = crypto_utils.decrypt(settings["helcim_api_token_encrypted"]) if settings else None
    data = request.get_json(force=True, silent=True) or {}
    transaction_id = data.get("transactionId")
    payment_ref = data.get("paymentRef")
    if not transaction_id or not payment_ref or not seller_token:
        return jsonify({"ok": False, "error": "Missing transaction/payment reference"}), 400

    with get_db() as conn:
        pending = conn.execute(
            "SELECT * FROM pending_payments WHERE ref=? AND kind='order' AND store_id=? AND order_id=?",
            (payment_ref, store["id"], order_id),
        ).fetchone()
        if not pending:
            return jsonify({"ok": False, "error": "Payment reference mismatch — refresh and try again."}), 400

        try:
            result = helcim.verify_transaction(transaction_id, pending["secret_token"], api_token=seller_token)
        except helcim.HelcimError as e:
            return jsonify({"ok": False, "error": str(e)}), 502

        approved = str(result.get("status", "")).lower() in ("approved", "success", "purchase")
        amount_ok = abs(float(result.get("amount", 0)) - order["total_cents"] / 100) < 0.01
        if not approved or not amount_ok:
            return jsonify({"ok": False, "error": "Transaction not approved or amount mismatch"}), 402

        conn.execute(
            "UPDATE orders SET paid=1, status='paid', helcim_transaction_id=? WHERE id=?",
            (str(transaction_id), order_id),
        )
        conn.execute("DELETE FROM pending_payments WHERE ref=?", (payment_ref,))
    return jsonify({"ok": True})


# ---------------------------------------------------------------- platform owner portal

def svg_sparkline(labels, values, width=640, height=140, accent="#1C7DE0"):
    """A tiny bar chart rendered as server-side inline SVG - no charting JS
    dependency, nothing fetched from a third party, nothing that can be tampered
    with client-side since the numbers are baked in at render time. The frontend
    drops this straight into the DOM as trusted markup (it's generated here from
    numbers only, never from user input)."""
    if not values or not any(values):
        return None
    pad_l, pad_r, pad_t, pad_b = 8, 8, 12, 22
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b
    n = len(values)
    bar_gap = 4
    bar_w = max(2, (plot_w - bar_gap * (n - 1)) / n) if n else plot_w
    vmax = max(values) or 1
    bars = []
    for i, v in enumerate(values):
        bh = (v / vmax) * plot_h if vmax else 0
        x = pad_l + i * (bar_w + bar_gap)
        y = pad_t + (plot_h - bh)
        bars.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w:.1f}" height="{max(bh,1):.1f}" rx="2" fill="{accent}"><title>{labels[i]}: {money(int(v))}</title></rect>')
    first_label = labels[0] if labels else ""
    last_label = labels[-1] if labels else ""
    text = (
        f'<text x="{pad_l}" y="{height-6}" font-size="10" fill="#8A94A6" font-family="IBM Plex Mono, monospace">{first_label}</text>'
        f'<text x="{width-pad_r}" y="{height-6}" font-size="10" fill="#8A94A6" text-anchor="end" font-family="IBM Plex Mono, monospace">{last_label}</text>'
    )
    return f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Revenue trend">{"".join(bars)}{text}</svg>'


def _revenue_trend(conn, store_id=None, days=14):
    since = (date.today() - timedelta(days=days - 1)).isoformat()
    q = "SELECT date(created_at) d, COALESCE(SUM(total_cents),0) t FROM orders WHERE paid=1 AND date(created_at) >= ?"
    params = [since]
    if store_id:
        q += " AND store_id=?"
        params.append(store_id)
    q += " GROUP BY d"
    rows = {r["d"]: r["t"] for r in conn.execute(q, params).fetchall()}
    labels, values = [], []
    for i in range(days):
        d = (date.today() - timedelta(days=days - 1 - i)).isoformat()
        labels.append(d[5:])  # MM-DD
        values.append(rows.get(d, 0))
    return labels, values


@app.route("/api/owner/overview")
@require_owner_auth
def owner_overview():
    with get_db() as conn:
        stores = conn.execute("SELECT * FROM stores ORDER BY created_at DESC").fetchall()

        top_sellers = conn.execute(
            """SELECT stores.id, stores.subdomain, stores.business_name, stores.owner_email,
                      COALESCE(SUM(CASE WHEN orders.paid=1 THEN orders.total_cents ELSE 0 END),0) AS revenue_cents,
                      COUNT(CASE WHEN orders.paid=1 THEN 1 END) AS paid_orders
               FROM stores LEFT JOIN orders ON orders.store_id = stores.id
               GROUP BY stores.id
               ORDER BY revenue_cents DESC, paid_orders DESC
               LIMIT 10"""
        ).fetchall()

        f_store = request.args.get("store", "").strip()
        f_status = request.args.get("status", "").strip()
        page = max(1, request.args.get("page", 1, type=int))
        per_page = 25

        where = ["1=1"]
        params = []
        if f_store:
            where.append("stores.subdomain = ?")
            params.append(f_store)
        if f_status == "unpaid":
            where.append("orders.paid = 0")
        elif f_status in ("paid", "confirmed", "shipped"):
            where.append("orders.paid = 1 AND orders.status = ?")
            params.append(f_status)
        where_sql = " AND ".join(where)

        total_matching = conn.execute(
            f"SELECT COUNT(*) c FROM orders JOIN stores ON stores.id = orders.store_id WHERE {where_sql}", params
        ).fetchone()["c"]
        total_pages = max(1, (total_matching + per_page - 1) // per_page)
        page = min(page, total_pages)

        orders = conn.execute(
            f"""SELECT orders.*, stores.subdomain, stores.business_name
                FROM orders JOIN stores ON stores.id = orders.store_id
                WHERE {where_sql}
                ORDER BY orders.created_at DESC LIMIT ? OFFSET ?""",
            params + [per_page, (page - 1) * per_page],
        ).fetchall()

        support_msgs = conn.execute("SELECT * FROM support_messages ORDER BY created_at DESC LIMIT 50").fetchall()
        setup_revenue_dollars = conn.execute("SELECT COUNT(*) c FROM stores WHERE setup_paid=1").fetchone()["c"] * SETUP_FEE_DOLLARS
        total_order_volume = conn.execute("SELECT COALESCE(SUM(total_cents),0) t FROM orders WHERE paid=1").fetchone()["t"]
        paid_order_count = conn.execute("SELECT COUNT(*) c FROM orders WHERE paid=1").fetchone()["c"]
        avg_order_cents = (total_order_volume / paid_order_count) if paid_order_count else 0

        # Plan revenue: the platform's own cut, separate from order volume (which is
        # sellers' money, routed straight to their own Helcim accounts).
        plan_revenue_cents = conn.execute("SELECT COALESCE(SUM(amount_cents),0) t FROM plan_payments").fetchone()["t"]
        plan_counts = {r["plan"]: r["c"] for r in conn.execute("SELECT plan, COUNT(*) c FROM stores GROUP BY plan").fetchall()}

        labels, values = _revenue_trend(conn)
        chart_svg = svg_sparkline(labels, values)
        store_plan_keys = {s["id"]: effective_plan_key(s, conn) for s in stores}

    return jsonify({
        "stores": [dict(store_to_dict(s, include_private=True), plan_effective=store_plan_keys[s["id"]]) for s in stores],
        "top_sellers": [
            {"id": s["id"], "subdomain": s["subdomain"], "business_name": s["business_name"],
             "owner_email": s["owner_email"], "revenue_cents": s["revenue_cents"], "paid_orders": s["paid_orders"]}
            for s in top_sellers
        ],
        "orders": [dict(order_to_dict(o, include_shipping=True), subdomain=o["subdomain"], business_name=o["business_name"]) for o in orders],
        "support_messages": [
            {"id": m["id"], "email": m["email"], "subject": m["subject"], "message": m["message"],
             "store_subdomain": m["store_subdomain"], "created_at": m["created_at"]}
            for m in support_msgs
        ],
        "setup_revenue_cents": int(round(setup_revenue_dollars * 100)),
        "total_order_volume_cents": total_order_volume,
        "avg_order_cents": int(avg_order_cents),
        "paid_order_count": paid_order_count,
        "plan_revenue_cents": plan_revenue_cents,
        "plan_counts": plan_counts,
        "chart_svg": chart_svg,
        "root_domain": ROOT_DOMAIN,
        "is_cut_off": site_is_cut_off(),
        "filters": {"store": f_store, "status": f_status, "page": page, "total_pages": total_pages},
    })


@app.route("/api/owner/stores/<int:store_id>")
@require_owner_auth
def owner_store_detail(store_id):
    with get_db() as conn:
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        if not store:
            abort(404)
        orders = conn.execute(
            "SELECT * FROM orders WHERE store_id=? ORDER BY created_at DESC LIMIT 200", (store_id,)
        ).fetchall()
        products = conn.execute(
            "SELECT * FROM products WHERE store_id=? ORDER BY created_at DESC", (store_id,)
        ).fetchall()
        revenue = conn.execute(
            "SELECT COALESCE(SUM(total_cents),0) t FROM orders WHERE store_id=? AND paid=1", (store_id,)
        ).fetchone()["t"]
        paid_count = conn.execute(
            "SELECT COUNT(*) c FROM orders WHERE store_id=? AND paid=1", (store_id,)
        ).fetchone()["c"]
        labels, values = _revenue_trend(conn, store_id=store_id)
        chart_svg = svg_sparkline(labels, values, accent=store["theme_color"] or "#1C7DE0")
        ok, plan_key, used, cap = plan_room_check(conn, store)
    return jsonify({
        "store": store_to_dict(store, include_private=True),
        "orders": [order_to_dict(o, include_shipping=True) for o in orders],
        "products": [product_to_dict(p) for p in products],
        "revenue_cents": revenue,
        "paid_count": paid_count,
        "chart_svg": chart_svg,
        "root_domain": ROOT_DOMAIN,
        "plan": plan_to_dict(plan_key),
        "used_cents": used,
        "cap_cents": cap,
    })


@app.route("/api/owner/stores/<int:store_id>/waive-setup", methods=["POST"])
@require_owner_auth
def owner_waive_setup(store_id):
    """Give a store a free website - waives the $25 setup fee without a real
    Helcim transaction behind it. Owner-only, never reachable from the seller
    side, and logged like any other sensitive action."""
    with get_db() as conn:
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        if not store:
            abort(404)
        conn.execute("UPDATE stores SET setup_paid=1 WHERE id=?", (store_id,))
        security.log_event(conn, "owner", OWNER_USERNAME, "setup_fee_waived", f"store #{store_id} ({store['subdomain']})")
    return jsonify({"ok": True})


@app.route("/api/owner/stores/<int:store_id>/comp", methods=["POST"])
@require_owner_auth
def owner_comp_store(store_id):
    """Gift a store unlimited access with no bill, ever - the only way onto the
    'comp' plan, which nothing on the seller side can grant or self-renew. Also
    waives the setup fee, since a comped store should just work."""
    with get_db() as conn:
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        if not store:
            abort(404)
        conn.execute(
            "UPDATE stores SET setup_paid=1, plan='comp', plan_started_at=?, plan_renews_at=NULL WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), store_id),
        )
        security.log_event(conn, "owner", OWNER_USERNAME, "store_comped", f"store #{store_id} ({store['subdomain']})")
    return jsonify({"ok": True})


@app.route("/api/owner/stores/<int:store_id>/uncomp", methods=["POST"])
@require_owner_auth
def owner_uncomp_store(store_id):
    """Take a comped store back to Starter. Doesn't touch setup_paid - once a site
    is live, dropping it back to unpaid would just break it for no reason."""
    with get_db() as conn:
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        if not store:
            abort(404)
        conn.execute("UPDATE stores SET plan='starter', plan_started_at=NULL, plan_renews_at=NULL WHERE id=?", (store_id,))
        security.log_event(conn, "owner", OWNER_USERNAME, "store_uncomped", f"store #{store_id} ({store['subdomain']})")
    return jsonify({"ok": True})


@app.route("/api/owner/stores/<int:store_id>/suspend", methods=["POST"])
@require_owner_auth
def owner_suspend_store(store_id):
    """Locks a store out immediately: login is blocked (even with the right
    password), the storefront shows as closed to buyers, and any active admin
    session for it is rejected on its very next request - see the suspended_at
    check in require_store_auth. Doesn't touch orders, products, or the plan;
    reversible any time with the unsuspend button."""
    data = request.get_json(force=True, silent=True) or {}
    reason = (data.get("reason") or "").strip()[:300]
    with get_db() as conn:
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        if not store:
            abort(404)
        if store["suspended_at"]:
            return jsonify({"error": "Already suspended."}), 400
        conn.execute(
            "UPDATE stores SET suspended_at=?, suspended_reason=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), reason or None, store_id),
        )
        security.log_event(conn, "owner", OWNER_USERNAME, "store_suspended", f"store #{store_id} ({store['subdomain']}): {reason or 'no reason given'}")
    return jsonify({"ok": True})


@app.route("/api/owner/stores/<int:store_id>/unsuspend", methods=["POST"])
@require_owner_auth
def owner_unsuspend_store(store_id):
    with get_db() as conn:
        store = conn.execute("SELECT * FROM stores WHERE id=?", (store_id,)).fetchone()
        if not store:
            abort(404)
        conn.execute("UPDATE stores SET suspended_at=NULL, suspended_reason=NULL WHERE id=?", (store_id,))
        security.log_event(conn, "owner", OWNER_USERNAME, "store_unsuspended", f"store #{store_id} ({store['subdomain']})")
    return jsonify({"ok": True})


@app.route("/api/owner/security")
@require_owner_auth
def owner_security():
    with get_db() as conn:
        events = conn.execute("SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 200").fetchall()
        locks = conn.execute(
            "SELECT * FROM auth_attempts WHERE locked_until IS NOT NULL ORDER BY updated_at DESC LIMIT 50"
        ).fetchall()
    return jsonify({
        "events": [dict(e) for e in events],
        "locks": [dict(l) for l in locks],
        "totp_enabled": _owner_2fa_enabled(),
        "pyotp_installed": bool(pyotp),
    })


def _csv_response(filename, header, rows):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(header)
    writer.writerows(rows)
    return Response(
        buf.getvalue(), mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/owner/export/orders.csv")
@require_owner_auth
def owner_export_orders():
    with get_db() as conn:
        orders = conn.execute(
            """SELECT orders.*, stores.subdomain FROM orders
               JOIN stores ON stores.id = orders.store_id ORDER BY orders.created_at DESC"""
        ).fetchall()
        security.log_event(conn, "owner", OWNER_USERNAME, "export_orders_csv")
    rows = [
        [o["id"], o["subdomain"], o["customer_name"], o["customer_email"], o["total_cents"] / 100,
         "paid" if o["paid"] else "unpaid", o["status"], o["created_at"]]
        for o in orders
    ]
    return _csv_response("orders.csv", ["order_id", "store", "customer_name", "customer_email", "total_cad", "paid", "status", "created_at"], rows)


@app.route("/api/owner/export/stores.csv")
@require_owner_auth
def owner_export_stores():
    with get_db() as conn:
        stores = conn.execute(
            """SELECT stores.*, COALESCE(SUM(CASE WHEN orders.paid=1 THEN orders.total_cents ELSE 0 END),0) revenue_cents,
                      COUNT(CASE WHEN orders.paid=1 THEN 1 END) paid_orders
               FROM stores LEFT JOIN orders ON orders.store_id = stores.id
               GROUP BY stores.id ORDER BY revenue_cents DESC"""
        ).fetchall()
        security.log_event(conn, "owner", OWNER_USERNAME, "export_stores_csv")
    rows = [
        [s["id"], s["subdomain"], s["business_name"], s["owner_email"], "yes" if s["setup_paid"] else "no",
         s["revenue_cents"] / 100, s["paid_orders"], s["created_at"]]
        for s in stores
    ]
    return _csv_response("stores.csv", ["store_id", "subdomain", "business_name", "owner_email", "setup_paid", "revenue_cad", "paid_orders", "created_at"], rows)


# ---------------------------------------------------------------- automatic payment confirmation (seller inbox)

import etransfer_verifier


@app.route("/api/email-settings", methods=["GET", "POST", "DELETE"])
@require_store_auth
@require_paid
def email_settings():
    if request.method == "DELETE":
        with get_db() as conn:
            conn.execute("DELETE FROM store_email_settings WHERE store_id=?", (g.store["id"],))
            security.log_event(conn, "store", g.store["owner_email"], "auto_verify_removed")
        return jsonify({"ok": True})

    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        host = (data.get("imap_host") or "").strip().lower()
        user = (data.get("imap_user") or "").strip()
        pw = (data.get("imap_password") or "").replace(" ", "")   # Google shows app passwords in 4-letter groups
        if not (host and user and pw) or "@" not in user:
            return jsonify({"error": "Enter the mail server, the email address, and the app password."}), 400
        try:
            etransfer_verifier.test_login(host, user, pw)         # outside any DB transaction: can take a few seconds
        except Exception as e:
            return jsonify({"error": "Couldn't log in to that mailbox (" + str(e)[:120] + "). Check the server name and use an app password, not your normal password."}), 400
        with get_db() as conn:
            conn.execute(
                """INSERT INTO store_email_settings (store_id, imap_host, imap_user, imap_pass_encrypted)
                   VALUES (?, ?, ?, ?)
                   ON CONFLICT(store_id) DO UPDATE SET imap_host=excluded.imap_host, imap_user=excluded.imap_user,
                     imap_pass_encrypted=excluded.imap_pass_encrypted, last_error=NULL, updated_at=CURRENT_TIMESTAMP""",
                (g.store["id"], host, user, crypto_utils.encrypt(pw)),
            )
            security.log_event(conn, "store", g.store["owner_email"], "auto_verify_enabled")

    with get_db() as conn:
        row = conn.execute("SELECT * FROM store_email_settings WHERE store_id=?", (g.store["id"],)).fetchone()
    return jsonify({
        "configured": bool(row),
        "imap_host": row["imap_host"] if row else None,
        "imap_user": row["imap_user"] if row else None,
        "last_checked_at": row["last_checked_at"] if row else None,
        "last_error": row["last_error"] if row else None,
        # the app password itself is never sent back out
    })


@app.route("/api/email-settings/test", methods=["POST"])
@require_store_auth
@require_paid
def email_test():
    """Paste a real notification email ('Show original' in Gmail) and see exactly what the
    reader would do with it. Read-only: nothing is marked paid."""
    raw = (request.get_json(force=True, silent=True) or {}).get("raw", "")
    if not raw.strip() or len(raw) > 300_000:
        return jsonify({"error": "Paste the full email (Gmail: three dots -> Show original)."}), 400
    with get_db() as conn:
        pend = etransfer_verifier.pending_orders(conn, g.store["id"])
        es = conn.execute("SELECT imap_user FROM store_email_settings WHERE store_id=?", (g.store["id"],)).fetchone()
    addrs = {a.lower() for a in (g.store["etransfer_email"], g.store["paypal_email"], es["imap_user"] if es else None) if a}
    return jsonify(etransfer_verifier.diagnose_message(raw, addrs, pend))


@app.route("/api/owner/test-email", methods=["POST"])
@require_owner_auth
def owner_test_email():
    raw = (request.get_json(force=True, silent=True) or {}).get("raw", "")
    if not raw.strip() or len(raw) > 300_000:
        return jsonify({"error": "Paste the full email (Gmail: three dots -> Show original)."}), 400
    addrs = {os.environ[k].lower() for k in ("PLATFORM_ETRANSFER_EMAIL", "PLATFORM_PAYPAL_EMAIL", "PLATFORM_IMAP_USER") if os.environ.get(k)}
    with get_db() as conn:
        pend = etransfer_verifier.pending_platform(conn)
    return jsonify(etransfer_verifier.diagnose_message(raw, addrs, pend))


# ---------------------------------------------------------------- platform fees paid by e-transfer / PayPal.me

def _platform_config():
    methods = {}
    if os.environ.get("PLATFORM_ETRANSFER_EMAIL"):
        methods["etransfer"] = {"email": os.environ["PLATFORM_ETRANSFER_EMAIL"]}
    if os.environ.get("PLATFORM_PAYPAL_ME"):
        methods["paypal"] = {"me": os.environ["PLATFORM_PAYPAL_ME"]}
    return methods


def _platform_auto():
    return bool(os.environ.get("PLATFORM_IMAP_USER") and os.environ.get("PLATFORM_IMAP_PASSWORD"))


def apply_platform_payment(conn, pay):
    """What 'this platform payment was confirmed' means. Called by the watcher (or
    the owner's manual confirm button) exactly once per payment."""
    sid, now = pay["store_id"], datetime.now(timezone.utc)
    if pay["kind"] == "setup_fee":
        conn.execute("UPDATE stores SET setup_paid=1 WHERE id=?", (sid,))
    elif pay["kind"] == "plan_upgrade":
        plan_key = pay["plan_key"]
        plan = PLANS[plan_key]
        row = conn.execute("SELECT plan, plan_started_at FROM stores WHERE id=?", (sid,)).fetchone()
        started = row["plan_started_at"] if row["plan"] == plan_key and row["plan_started_at"] else now.isoformat()
        renews = (now + timedelta(days=PLAN_PERIOD_DAYS)).isoformat() if plan["kind"] == "flat" else None
        conn.execute("UPDATE stores SET plan=?, plan_started_at=?, plan_renews_at=? WHERE id=?", (plan_key, started, renews, sid))
        conn.execute("INSERT INTO plan_payments (store_id, plan, amount_cents, helcim_transaction_id) VALUES (?, ?, ?, ?)",
                     (sid, plan_key, pay["expected_cents"], "platform:" + pay["ref"]))
    elif pay["kind"] == "plan_invoice":
        conn.execute("UPDATE plan_invoices SET paid=1, paid_at=?, helcim_transaction_id=? WHERE id=? AND store_id=?",
                     (now.isoformat(), "platform:" + pay["ref"], pay["invoice_id"], sid))
        conn.execute("INSERT INTO plan_payments (store_id, plan, amount_cents, helcim_transaction_id) VALUES (?, 'scale', ?, ?)",
                     (sid, pay["expected_cents"], "platform:" + pay["ref"]))


etransfer_verifier.register_platform_effect(apply_platform_payment)


@app.route("/api/platform-pay/options")
@require_store_auth
def platform_pay_options():
    return jsonify({
        "methods": _platform_config(),
        "auto": _platform_auto(),
        "helcim": bool(os.environ.get("HELCIM_API_TOKEN")),
    })


@app.route("/api/platform-pay/start", methods=["POST"])
@require_store_auth
def platform_pay_start():
    data = request.get_json(force=True, silent=True) or {}
    kind, method, plan_key = data.get("kind"), data.get("method"), data.get("plan_key")
    cfg = _platform_config()
    if method not in cfg:
        return jsonify({"error": "That payment method isn't available."}), 400
    store = g.store
    if kind != "setup_fee" and not store["setup_paid"]:
        return jsonify({"error": "Pay the setup fee first.", "code": "setup_fee_required"}), 402

    with get_db() as conn:
        invoice_id = None
        if kind == "setup_fee":
            if store["setup_paid"]:
                return jsonify({"error": "Setup fee is already paid."}), 400
            base = int(SETUP_FEE_DOLLARS * 100)
        elif kind == "plan_upgrade":
            if plan_key not in PLAN_ORDER or plan_key == "starter":
                return jsonify({"error": "Not a valid plan."}), 400
            credit = growth_fee_credit_cents(conn, store) if plan_key == "growth" else 0
            base = max(int(PLANS[plan_key]["price_dollars"] * 100) - credit, 0)
        elif kind == "plan_invoice":
            get_or_create_scale_invoice(conn, store)
            inv = _current_open_invoice(conn, store)
            if not inv:
                return jsonify({"error": "Nothing owing right now."}), 400
            base, invoice_id = inv["amount_cents"], inv["id"]
        else:
            return jsonify({"error": "Unknown payment type."}), 400

        row = conn.execute(
            """SELECT * FROM platform_payments WHERE store_id=? AND kind=? AND COALESCE(plan_key,'')=COALESCE(?,'')
               AND COALESCE(invoice_id,0)=COALESCE(?,0) AND method=? AND status='pending' AND base_cents=?
               AND created_at >= datetime('now','-72 hours')""",
            (store["id"], kind, plan_key, invoice_id, method, base),
        ).fetchone()
        if not row:
            taken = {r[0] for r in conn.execute(
                "SELECT expected_cents FROM platform_payments WHERE status='pending' AND created_at >= datetime('now','-72 hours')").fetchall()}
            expected, bump = base, 0
            while expected in taken and bump < 99:
                bump += 1
                expected = base + bump
            ref = gen_ref("PELT")
            cur = conn.execute(
                """INSERT INTO platform_payments (store_id, kind, plan_key, invoice_id, method, ref, base_cents, expected_cents)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (store["id"], kind, plan_key, invoice_id, method, ref, base, expected),
            )
            row = conn.execute("SELECT * FROM platform_payments WHERE id=?", (cur.lastrowid,)).fetchone()

    out = {"ref": row["ref"], "method": method, "kind": kind, "amount_cents": row["expected_cents"],
           "base_cents": row["base_cents"], "auto": _platform_auto()}
    if method == "etransfer":
        out["email"] = cfg["etransfer"]["email"]
    else:
        out["paypal_link"] = paypal_link(cfg["paypal"]["me"], row["expected_cents"])
    return jsonify(out)


@app.route("/api/platform-pay/<ref>")
@require_store_auth
def platform_pay_status(ref):
    with get_db() as conn:
        row = conn.execute("SELECT status, kind FROM platform_payments WHERE ref=? AND store_id=?", (ref, g.store["id"])).fetchone()
    if not row:
        abort(404)
    return jsonify({"status": row["status"], "kind": row["kind"]})


@app.route("/api/owner/platform-payments")
@require_owner_auth
def owner_platform_payments():
    with get_db() as conn:
        rows = conn.execute(
            """SELECT p.*, s.subdomain FROM platform_payments p JOIN stores s ON s.id = p.store_id
               ORDER BY p.created_at DESC LIMIT 50""").fetchall()
    return jsonify({"payments": [dict(r) for r in rows], "auto": _platform_auto(), "methods": list(_platform_config())})


@app.route("/api/owner/platform-payments/<int:pid>/confirm", methods=["POST"])
@require_owner_auth
def owner_confirm_platform_payment(pid):
    """Manual fallback: you saw the money land, so confirm it by hand."""
    with get_db() as conn:
        row = conn.execute("SELECT * FROM platform_payments WHERE id=?", (pid,)).fetchone()
        if not row:
            abort(404)
        cur = conn.execute("UPDATE platform_payments SET status='paid', paid_at=? WHERE id=? AND status='pending'",
                           (datetime.now(timezone.utc).isoformat(), pid))
        if cur.rowcount:
            apply_platform_payment(conn, row)
            security.log_event(conn, "owner", OWNER_USERNAME, "platform_payment_confirmed_manually", f"payment #{pid}")
    return jsonify({"ok": True})


@app.route("/api/owner/fee-whatif")
@require_owner_auth
def owner_fee_whatif():
    """Estimates only - no money moves. What each store would cost YOU in Helcim
    fees if its sales ran through a Helcim account of yours: this month so far, and
    projected at the store's plan cap. Rates: ACH 0.5% + $0.25 (max $6); card
    ~2.49% + $0.25 typical, 3% + $0.25 as a pessimistic case."""
    ach = lambda a: min(round(a * 0.005) + 25, 600)
    card = lambda a: round(a * 0.0249) + 25
    card_hi = lambda a: round(a * 0.03) + 25
    rows = []
    with get_db() as conn:
        for s in conn.execute("SELECT * FROM stores ORDER BY created_at DESC").fetchall():
            m = conn.execute(
                "SELECT COUNT(*) c, COALESCE(SUM(total_cents),0) t FROM orders WHERE store_id=? AND paid=1 AND date(created_at) >= ?",
                (s["id"], _month_start_iso())).fetchone()
            avg = int(m["t"] / m["c"]) if m["c"] else 2500
            plan_key = effective_plan_key(s, conn)
            cap = PLANS[plan_key]["cap_cents"]
            proj_cap = cap if cap is not None else 1_000_000
            n_cap = max(1, round(proj_cap / avg))
            rows.append({
                "store_id": s["id"], "subdomain": s["subdomain"], "plan": plan_key,
                "month_orders": m["c"], "month_volume_cents": m["t"], "avg_order_cents": avg,
                "avg_is_assumed": m["c"] == 0,
                "per_order": {"ach_cents": ach(avg), "card_cents": card(avg), "card_high_cents": card_hi(avg)},
                "month_so_far": {"ach_cents": sum([ach(avg)] * m["c"]), "card_cents": sum([card(avg)] * m["c"])},
                "at_cap": {
                    "cap_cents": proj_cap, "cap_is_assumed": cap is None, "orders": n_cap,
                    "ach_cents": ach(avg) * n_cap, "card_cents": card(avg) * n_cap, "card_high_cents": card_hi(avg) * n_cap,
                },
            })
    return jsonify({"stores": rows})


if __name__ == "__main__":
    debug = os.environ.get("FLASK_ENV") == "development"
    # Start the payment watcher once (the dev reloader runs this file twice; only the child should).
    if not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        etransfer_verifier.start_background()
    app.run(debug=debug, port=int(os.environ.get("PORT", 5000)), host="0.0.0.0")
