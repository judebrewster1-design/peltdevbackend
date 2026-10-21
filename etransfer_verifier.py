"""
Automatic payment confirmation from notification emails.

A buyer pays a seller by Interac e-Transfer or a PayPal.me link. The seller's
bank / PayPal then emails the seller "you got paid". This module reads that
inbox (read-only, IMAP) and marks the matching order paid - no manual step.

An email can only mark something paid if ALL of these hold:
  1. It is from a known bank / Interac / PayPal domain.
  2. The seller's OWN mail provider recorded a passing DKIM/DMARC result for
     that domain (only the topmost Authentication-Results header is trusted -
     that's the one the receiving server added, not one a sender typed in).
  3. It is addressed (To:) to one of the seller's own addresses. The To header is
     covered by the bank's signature, so a real deposit email meant for someone
     else can't be re-sent here to pay an order.
  4. The amount matches an unpaid order's expected amount exactly. Amounts
     labelled fee / net / balance / tax etc. are ignored.
  5. It is newer than the order and the order is under 72 hours old.
  6. This exact email (Message-ID) has never been used before.

Nothing email-based is mathematically unforgeable. This makes forging one need
a real bank-signed email addressed to the seller for the exact amount - which is
a real payment. A manual "mark paid" button remains as the fallback.
"""
import email
import hashlib
import html
import imaplib
import os
import re
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from email.header import decode_header, make_header
from email.utils import getaddresses, parseaddr, parsedate_to_datetime

from db import get_db
import crypto_utils

MATCH_WINDOW_HOURS = 72
FAST_POLL_SECONDS = 30       # while a recent order is waiting on money
SLOW_POLL_SECONDS = 300      # once every pending order is over 10 minutes old
FRESH_ORDER_MINUTES = 10

PAYPAL_DOMAINS = ["paypal.com", "paypal.ca"]
DEFAULT_BANK_DOMAINS = [
    "interac.ca", "rbc.com", "rbcroyalbank.com", "td.com", "bmo.com", "scotiabank.com",
    "cibc.com", "desjardins.com", "tangerine.ca", "simplii.com", "nbc.ca", "nbf.ca",
    "atb.com", "eqbank.ca", "wealthsimple.com", "koho.ca", "manulife.ca", "meridiancu.ca",
]


def bank_domains():
    raw = os.environ.get("ETRANSFER_SENDER_DOMAINS")
    if raw:
        return [d.strip().lower() for d in raw.split(",") if d.strip()]
    return DEFAULT_BANK_DOMAINS


def all_domains():
    return bank_domains() + PAYPAL_DOMAINS


# ---------------------------------------------------------------- parsing

AMOUNT_RE = re.compile(r"\$\s?((?:\d{1,3}(?:,\d{3})+|\d+)\.\d{2})")
REF_RE = re.compile(r"\b((?:ORD|PELT)-[A-Z0-9]{6})\b", re.I)
SKIP_LABELS = ("fee", "net", "balance", "available", "tax", "shipping", "handling", "refund")
HINTS = (
    "e-transfer", "etransfer", "interac", "autodeposit", "deposited", "deposit",
    "you've got money", "you got money", "you received", "you've received", "you have received",
    "received a payment", "received money", "money received", "payment received",
    "sent you", "paid you", "notification of payment",
    # Quebec / French notices
    "virement", "vous avez reçu", "vous a envoyé", "dépôt", "a été déposé",
)
# Notices that mention an amount but are NOT money arriving: outgoing payments, refunds,
# pending/held/declined items, withdrawals. Checked against the subject + first 400 characters only,
# so boilerplate further down a real receipt (e.g. dispute wording) can't block it.
NEGATIVE_HEADLINE = (
    "you sent", "you've sent", "you have sent", "you paid", "you've paid", "your payment to", "payment sent",
    "refund", "reversal", "chargeback", "dispute", "withdraw", "transfer to your bank", "requested",
    "request for", "declined", "cancel", "expired", "pending", "on hold", "you're sending",
    "vous avez envoy", "remboursement", "annul", "en attente",
)
# French-Canadian amounts look like "14,55 $" or "1 234,56 $"
AMOUNT_RE_FR = re.compile(r"((?:\d{1,3}(?:[\s\u00a0]\d{3})+|\d+)),(\d{2})\s?\$")


def _to_cents(s):
    return int(round(float(s.replace(",", "")) * 100))


def _flatten(msg):
    parts = []
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            payload = part.get_payload(decode=True)
            if payload is None:
                continue
            text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        except Exception:
            continue
        if ctype == "text/html":
            text = re.sub(r"<(script|style).*?</\1>", " ", text, flags=re.S | re.I)
            text = re.sub(r"<[^>]+>", " ", text)
            text = html.unescape(text)
        parts.append(text)
    return re.sub(r"\s+", " ", " ".join(parts))


def primary_amounts(text):
    """Dollar amounts in the email that are NOT labelled as a fee / net / balance /
    tax etc. (PayPal receipts list gross, fee and net side by side)."""
    out = set()
    found = [(m.start(), _to_cents(m.group(1))) for m in AMOUNT_RE.finditer(text)]
    found += [(m.start(), _to_cents(re.sub(r"[\s\u00a0]", "", m.group(1)) + "." + m.group(2))) for m in AMOUNT_RE_FR.finditer(text)]
    for start, cents in found:
        before = text[max(0, start - 30):start].lower()
        label = re.split(r"\$|cad|usd", before)[-1]
        if any(k in label for k in SKIP_LABELS + ("frais", "solde", "montant net")):
            continue
        out.add(cents)
    return out


def _domain_ok(domain, allowed):
    domain = (domain or "").lower().rstrip(".")
    return any(domain == d or domain.endswith("." + d) for d in allowed)


def passes_authentication(msg, allowed):
    headers = msg.get_all("Authentication-Results") or []
    if not headers:
        return False
    top = str(headers[0]).lower()          # topmost = added last = by the seller's own mail server
    for m in re.finditer(r"dkim=pass[^;]*", top):
        d = re.search(r"header\.(?:d|i)=@?([a-z0-9.\-]+)", m.group(0))
        if d and _domain_ok(d.group(1), allowed):
            return True
    if "dmarc=pass" in top:
        hf = re.search(r"header\.from=([a-z0-9.\-]+)", top)
        if hf and _domain_ok(hf.group(1), allowed):
            return True
    return False


def _to_addresses(msg):
    return {a.lower() for _, a in getaddresses(msg.get_all("To", []) or []) if a}


def _subject(msg):
    try:
        return str(make_header(decode_header(msg.get("Subject", ""))))
    except Exception:
        return msg.get("Subject", "") or ""


def _parse_ts(ts):
    """SQLite CURRENT_TIMESTAMP ('YYYY-MM-DD HH:MM:SS', UTC) -> aware datetime."""
    try:
        dt = datetime.fromisoformat(ts)
    except ValueError:
        dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _headline(msg, text):
    return (_subject(msg) + " " + text[:400]).lower().replace("\u2019", "'")


def _cents_str(c):
    return "$%.2f" % (c / 100)


def diagnose_message(raw, mailbox_addrs, pendings):
    """Explains, check by check, what the payment reader would do with a pasted email.
    Changes nothing. Uses the same helpers as evaluate_message so the answer can't drift."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", errors="replace")
    msg = email.message_from_bytes(raw)
    allowed = all_domains()
    checks = []
    add = lambda name, ok, detail: checks.append({"name": name, "ok": bool(ok), "detail": detail})

    from_addr = parseaddr(msg.get("From", ""))[1]
    from_domain = from_addr.rsplit("@", 1)[-1].lower()
    add("Sent by a bank, Interac or PayPal", _domain_ok(from_domain, allowed),
        "From: " + (from_addr or "not found - paste the full 'Show original' text, headers included"))

    ar = msg.get_all("Authentication-Results") or []
    add("Your mail provider verified the sender's signature", passes_authentication(msg, allowed),
        ("Provider said: " + str(ar[0])[:160].replace("\n", " ")) if ar else
        "No Authentication-Results header found. Paste the whole 'Show original' text, not just the message body.")

    to = _to_addresses(msg)
    need_to = os.environ.get("ETRANSFER_REQUIRE_TO_MATCH", "1") != "0"
    add("Addressed to you", (not need_to) or bool(to & {a.lower() for a in mailbox_addrs}),
        "To: " + (", ".join(sorted(to)) or "none found") + " | your addresses: " + (", ".join(sorted(mailbox_addrs)) or "none set yet"))

    text = _flatten(msg)
    hay = (_subject(msg) + " " + text[:3000]).lower().replace("\u2019", "'")
    pos = [h for h in HINTS if h in hay]
    add("Reads like a payment-received notice", bool(pos), ("Matched: " + ", ".join(pos[:4])) if pos else "Subject: " + _subject(msg)[:100])
    neg = [n for n in NEGATIVE_HEADLINE if n in _headline(msg, text)]
    add("Not a refund, outgoing, or pending notice", not neg, ("Looks like one because of: " + ", ".join(neg)) if neg else "OK")

    amounts = sorted(primary_amounts(text))
    add("Found a payment amount", bool(amounts), ", ".join(_cents_str(a) for a in amounts) or "No dollar amounts found outside fee/net/balance lines")
    try:
        parsedate_to_datetime(msg["Date"])
        add("Has a usable date", True, str(msg["Date"]))
    except Exception:
        add("Has a usable date", False, "Date header missing or unreadable")

    outcome, p = evaluate_message(msg, mailbox_addrs, pendings)
    if outcome == "paid":
        message = f"This email WOULD mark order/payment #{p['id']} paid ({_cents_str(p['expected_cents'])})."
    else:
        # The real reason always comes first - a forged/wrong-sender email is
        # rejected regardless of whether any order exists to match it against,
        # and saying so up front matters more here than anywhere else in this
        # file: this is the one tool a seller reads with their own eyes.
        why = {"rejected_sender": "the sender isn't a bank/Interac/PayPal address", "rejected_auth": "the signature check didn't pass",
               "rejected_recipient": "it isn't addressed to you", "ignored": "it doesn't read like money arriving",
               "rejected_date": "the date is unreadable", "amount_mismatch": "the amount doesn't equal what the order expects",
               "ambiguous": "more than one order expects that amount", "no_match": "no unpaid order expects any amount in it (or it is older than the order)"}
        message = "This email would NOT pay anything: " + why.get(outcome, outcome) + "."
        if outcome == "no_match" and not pendings:
            message += " (There's also no unpaid order waiting right now - place a test order at your own store for the same amount to test the matching step too.)"
    return {"checks": checks, "amounts": amounts, "verdict": outcome, "message": message,
            "waiting_for": [{"id": q["id"], "method": q["method"], "amount": _cents_str(q["expected_cents"])} for q in pendings]}


def evaluate_message(msg, mailbox_addrs, pendings):
    """Pure decision function. pendings: [{id, table, method, ref, expected_cents,
    created_at(aware)}]. Returns (outcome, pending_or_None)."""
    allowed = all_domains()
    from_domain = parseaddr(msg.get("From", ""))[1].rsplit("@", 1)[-1].lower()
    if not _domain_ok(from_domain, allowed):
        return "rejected_sender", None
    if not passes_authentication(msg, allowed):
        return "rejected_auth", None
    if os.environ.get("ETRANSFER_REQUIRE_TO_MATCH", "1") != "0":
        if not (_to_addresses(msg) & {a.lower() for a in mailbox_addrs}):
            return "rejected_recipient", None

    text = _flatten(msg)
    hay = (_subject(msg) + " " + text[:3000]).lower().replace("\u2019", "'")   # curly -> straight apostrophe
    if not any(h in hay for h in HINTS):
        return "ignored", None
    if any(n in _headline(msg, text) for n in NEGATIVE_HEADLINE):
        return "ignored", None

    try:
        sent_at = parsedate_to_datetime(msg["Date"])
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)
    except Exception:
        return "rejected_date", None

    method = "paypal" if _domain_ok(from_domain, PAYPAL_DOMAINS) else "etransfer"
    cands = [p for p in pendings if p["method"] == method and sent_at >= p["created_at"] - timedelta(minutes=5)]
    amounts = primary_amounts(text)
    refs = {r.upper() for r in REF_RE.findall(text)}

    by_ref = [p for p in cands if p["ref"] and p["ref"].upper() in refs]
    if by_ref:
        p = by_ref[0]
        return ("paid", p) if p["expected_cents"] in amounts else ("amount_mismatch", p)

    hits = [p for p in cands if p["expected_cents"] in amounts]
    if len(hits) == 1:
        return "paid", hits[0]
    if len(hits) > 1:
        return "ambiguous", None
    return "no_match", None


# ---------------------------------------------------------------- applying a match

_platform_effect = None


def register_platform_effect(fn):
    """app.py registers what 'a platform payment was confirmed' means (activate the
    store / upgrade the plan / mark the invoice paid)."""
    global _platform_effect
    _platform_effect = fn


def _audit(conn, action, detail=""):
    conn.execute(
        "INSERT INTO audit_log (actor_type, actor_label, action, detail, ip) VALUES ('system', 'payment-watcher', ?, ?, 'watcher')",
        (action, detail),
    )


def _apply_paid(conn, p):
    if p["table"] == "orders":
        cur = conn.execute("UPDATE orders SET paid=1, status='paid' WHERE id=? AND paid=0", (p["id"],))
        if cur.rowcount:
            _audit(conn, "order_paid_via_email", f"order #{p['id']} ({p['method']})")
    else:
        cur = conn.execute(
            "UPDATE platform_payments SET status='paid', paid_at=? WHERE id=? AND status='pending'",
            (datetime.now(timezone.utc).isoformat(), p["id"]),
        )
        if cur.rowcount and _platform_effect:
            row = conn.execute("SELECT * FROM platform_payments WHERE id=?", (p["id"],)).fetchone()
            _platform_effect(conn, row)
            _audit(conn, "platform_payment_via_email", f"{row['kind']} store #{row['store_id']} ({p['method']})")


def process_raw_messages(conn, scope_id, mailbox_addrs, pendings, raw_messages):
    """scope_id: store id, or 0 for the platform's own mailbox. Every email is
    recorded before it's judged, so it can never be counted twice."""
    results = []
    for raw in raw_messages:
        msg = email.message_from_bytes(raw)
        mid = (msg.get("Message-ID") or "").strip() or "sha256:" + hashlib.sha256(raw).hexdigest()
        try:
            conn.execute("INSERT INTO processed_emails (store_id, message_id) VALUES (?, ?)", (scope_id, mid))
        except sqlite3.IntegrityError:
            continue
        outcome, p = evaluate_message(msg, mailbox_addrs, pendings)
        if outcome == "paid":
            _apply_paid(conn, p)
            pendings.remove(p)
        conn.execute(
            "UPDATE processed_emails SET outcome=?, order_id=? WHERE store_id=? AND message_id=?",
            (outcome, p["id"] if p else None, scope_id, mid),
        )
        if outcome in ("rejected_auth", "rejected_recipient"):
            _audit(conn, "payment_email_suspicious", f"{outcome} (scope {scope_id})")
        results.append((mid, outcome, p["id"] if p else None))
    return results


# ---------------------------------------------------------------- IMAP

def _or_from(domains):
    if len(domains) == 1:
        return f'FROM "{domains[0]}"'
    return f'OR FROM "{domains[0]}" ({_or_from(domains[1:])})'


def build_search(days=3):
    since = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%d-%b-%Y")
    return ["SINCE", since, "(" + _or_from(all_domains()) + ")"]


def fetch_recent_raw(host, user, password, max_messages=60, timeout=20):
    """Read-only (nothing is marked read, moved or deleted), and the server does the
    filtering: only recent mail from bank/PayPal senders is ever downloaded."""
    conn = imaplib.IMAP4_SSL(host, 993, timeout=timeout)
    raws = []
    try:
        conn.login(user, password)
        conn.select("INBOX", readonly=True)
        status, data = conn.search(None, *build_search())
        if status != "OK":
            return raws
        for mid in data[0].split()[-max_messages:]:
            st, md = conn.fetch(mid, "(BODY.PEEK[])")
            if st == "OK" and md and md[0] and isinstance(md[0], tuple):
                raws.append(md[0][1])
    finally:
        try:
            conn.logout()
        except Exception:
            pass
    return raws


def test_login(host, user, password):
    c = imaplib.IMAP4_SSL(host, 993, timeout=15)
    try:
        c.login(user, password)
    finally:
        try:
            c.logout()
        except Exception:
            pass


# ---------------------------------------------------------------- pending items

def pending_orders(conn, store_id):
    rows = conn.execute(
        """SELECT id, payment_method, payment_ref, total_cents, etransfer_amount_cents, created_at
           FROM orders WHERE store_id=? AND paid=0 AND payment_method IN ('etransfer','paypal')
           AND created_at >= datetime('now', ?)""",
        (store_id, f"-{MATCH_WINDOW_HOURS} hours"),
    ).fetchall()
    return [{
        "id": r["id"], "table": "orders", "method": r["payment_method"], "ref": r["payment_ref"],
        "expected_cents": r["etransfer_amount_cents"] or r["total_cents"], "created_at": _parse_ts(r["created_at"]),
    } for r in rows]


def pending_platform(conn):
    rows = conn.execute(
        "SELECT * FROM platform_payments WHERE status='pending' AND created_at >= datetime('now', ?)",
        (f"-{MATCH_WINDOW_HOURS} hours",),
    ).fetchall()
    return [{
        "id": r["id"], "table": "platform_payments", "method": r["method"], "ref": r["ref"],
        "expected_cents": r["expected_cents"], "created_at": _parse_ts(r["created_at"]),
    } for r in rows]


def platform_mailbox():
    user = os.environ.get("PLATFORM_IMAP_USER")
    pw = os.environ.get("PLATFORM_IMAP_PASSWORD")
    if not (user and pw):
        return None
    addrs = {user.lower()}
    for k in ("PLATFORM_ETRANSFER_EMAIL", "PLATFORM_PAYPAL_EMAIL"):
        if os.environ.get(k):
            addrs.add(os.environ[k].lower())
    return os.environ.get("PLATFORM_IMAP_HOST", "imap.gmail.com"), user, pw, addrs


# ---------------------------------------------------------------- the loop

_last_check = {}


def _due(key, pendings):
    now = datetime.now(timezone.utc)
    fresh = any(now - p["created_at"] < timedelta(minutes=FRESH_ORDER_MINUTES) for p in pendings)
    interval = FAST_POLL_SECONDS if fresh else SLOW_POLL_SECONDS
    if time.monotonic() - _last_check.get(key, -1e9) < interval - 1:
        return False
    _last_check[key] = time.monotonic()
    return True


def check_all_once():
    with get_db() as conn:
        stores = conn.execute(
            """SELECT s.id, s.etransfer_email, s.paypal_email, e.imap_host, e.imap_user, e.imap_pass_encrypted
               FROM stores s JOIN store_email_settings e ON e.store_id = s.id"""
        ).fetchall()
    for s in stores:
        with get_db() as conn:
            pendings = pending_orders(conn, s["id"])
        if not pendings or not _due(("store", s["id"]), pendings):
            continue   # nothing waiting on money -> no login at all
        addrs = {a.lower() for a in (s["imap_user"], s["etransfer_email"], s["paypal_email"]) if a}
        try:
            raws = fetch_recent_raw(s["imap_host"], s["imap_user"], crypto_utils.decrypt(s["imap_pass_encrypted"]))
            with get_db() as conn:
                process_raw_messages(conn, s["id"], addrs, pendings, raws)
                conn.execute("UPDATE store_email_settings SET last_checked_at=?, last_error=NULL WHERE store_id=?",
                             (datetime.now(timezone.utc).isoformat(), s["id"]))
        except Exception as e:
            with get_db() as conn:
                conn.execute("UPDATE store_email_settings SET last_error=? WHERE store_id=?", (str(e)[:200], s["id"]))

    box = platform_mailbox()
    if box:
        host, user, pw, addrs = box
        with get_db() as conn:
            pendings = pending_platform(conn)
        if pendings and _due(("platform",), pendings):
            try:
                raws = fetch_recent_raw(host, user, pw)
                with get_db() as conn:
                    process_raw_messages(conn, 0, addrs, pendings, raws)
            except Exception as e:
                print("[payment-watcher] platform mailbox error:", str(e)[:200])


def start_background(poll_seconds=15):
    def loop():
        while True:
            try:
                check_all_once()
            except Exception as e:
                print("[payment-watcher] error:", str(e)[:200])
            time.sleep(poll_seconds)
    threading.Thread(target=loop, daemon=True, name="payment-watcher").start()
