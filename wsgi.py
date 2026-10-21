"""Production entry point: gunicorn wsgi:app

Starts the payment-watcher thread once. Run gunicorn with exactly ONE worker
process (see deploy/peltdev.service) so there is one watcher and SQLite never
has competing writers; threads handle concurrency.
"""
import etransfer_verifier
from app import app  # noqa: F401  (init_db etc. run on import)

etransfer_verifier.start_background()
