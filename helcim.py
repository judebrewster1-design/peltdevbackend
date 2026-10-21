"""
Helcim payment integration (HelcimPay.js).

Two separate uses in this app:

1. PLATFORM setup fee ($25 CAD) — charged to the platform's own Helcim
   account. Configure with HELCIM_API_TOKEN (platform env var).

2. Per-store customer orders — charged straight into that STORE OWNER'S
   OWN Helcim account. Each seller signs up for their own Helcim merchant
   account (Helcim underwrites/verifies each merchant directly — there's
   no "connect with one click" marketplace API for this), gets their own
   Account ID + API token from their Helcim dashboard, and enters them in
   /admin/payment-settings. From then on, their customers' money goes
   straight to their own bank. This platform never touches it.

Flow (same for both cases): initialize() on the backend -> checkoutToken
-> HelcimPay.js modal on the frontend -> customer pays -> frontend gets a
SUCCESS/ABORTED message -> backend re-verifies with verify_transaction()
before marking anything paid. Never trust the frontend message alone.

CONFIRM AGAINST HELCIM'S CURRENT DOCS BEFORE GOING LIVE
--------------------------------------------------------
This follows the documented HelcimPay.js pattern (initialize -> checkoutToken/
secretToken -> appendHelcimPayIframe -> verify), but Helcim's exact request/
response field names do shift between API versions. Test end-to-end against
Helcim's sandbox before charging anyone for real.
"""
import os
import requests

HELCIM_API_BASE = "https://api.helcim.com/v2"
PLATFORM_HELCIM_API_TOKEN = os.environ.get("HELCIM_API_TOKEN")
# 'ach' = bank-to-bank (account-to-account) — the low/no-fee option this platform is built around.
# Use 'cc' for card, or check Helcim's docs for a combined option if you want to offer both.
HELCIM_PAYMENT_METHOD = os.environ.get("HELCIM_PAYMENT_METHOD", "ach")


class HelcimError(Exception):
    pass


def initialize_checkout(amount_dollars, currency="CAD", api_token=None, description=None):
    """Starts a HelcimPay.js session. Returns (checkout_token, secret_token).
    Pass api_token explicitly to charge into a SELLER's own account instead of the platform's."""
    token = api_token or PLATFORM_HELCIM_API_TOKEN
    if not token:
        raise HelcimError("No Helcim API token configured.")

    payload = {
        "paymentType": "purchase",
        "amount": round(amount_dollars, 2),
        "currency": currency,
        "paymentMethod": HELCIM_PAYMENT_METHOD,
    }
    if description:
        payload["invoiceNumber"] = description[:50]

    resp = requests.post(
        f"{HELCIM_API_BASE}/helcim-pay/initialize",
        headers={"api-token": token, "content-type": "application/json", "accept": "application/json"},
        json=payload,
        timeout=15,
    )
    if resp.status_code != 200:
        raise HelcimError(f"Helcim initialize failed ({resp.status_code}): {resp.text}")
    data = resp.json()
    checkout_token = data.get("checkoutToken")
    secret_token = data.get("secretToken")
    if not checkout_token or not secret_token:
        raise HelcimError(f"Unexpected Helcim initialize response: {data}")
    return checkout_token, secret_token


def verify_transaction(transaction_id, secret_token, api_token=None):
    """Re-checks a transaction server-side rather than trusting the browser's
    postMessage event. Adjust the endpoint/fields here to match whatever
    Helcim's current 'verify transaction' or 'get transaction' reference says —
    this is the one call in the whole integration you want to test for real
    before launch."""
    token = api_token or PLATFORM_HELCIM_API_TOKEN
    resp = requests.get(
        f"{HELCIM_API_BASE}/card-transactions/{transaction_id}",
        headers={"api-token": token, "accept": "application/json"},
        timeout=15,
    )
    if resp.status_code != 200:
        raise HelcimError(f"Helcim verify failed ({resp.status_code}): {resp.text}")
    return resp.json()
