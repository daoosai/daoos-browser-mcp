"""Billing consumes immutable usage events; it never executes browser commands."""
from typing import Protocol
from decimal import Decimal


class BillingProvider(Protocol):
    def create_topup(self, account_id: str, amount: Decimal, currency: str, idempotency_key: str) -> dict: ...
    def verify_webhook(self, body: bytes, signature: str) -> dict: ...
    def reconcile(self, account_id: str) -> dict: ...


class NoPayments:
    def create_topup(self, *args, **kwargs):
        raise NotImplementedError("Payments are disabled in MVP")
