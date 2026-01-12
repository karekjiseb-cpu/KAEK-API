import os
import hmac
import hashlib
import logging
from typing import Any, Dict, List
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Header, HTTPException

from stripe_service import create_stripe_payout
from database import init_db, record_transaction

# ---------------- Logging ----------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("webhook")

load_dotenv()

app = FastAPI()

# ---------------- Env / Flags ----------------
# Shared secret used to sign the raw request body
SHARED_SECRET = os.getenv("KAEKSHAREDSECRET", "").encode("utf-8")

# Dev flags to make testing easier
VERIFY_SIGNATURE = os.getenv("VERIFY_SIGNATURE", "true").lower() == "true"
DISABLE_STRIPE = os.getenv("DISABLE_STRIPE", "false").lower() == "true"

SUPPORTED_CURRENCIES = {"USD", "EUR", "GBP"}

# Init DB at startup
init_db()


def _compute_signature(secret: bytes, body: bytes) -> str:
    """Return hex HMAC-SHA256 signature of request body."""
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def _normalize_signature(sig: str) -> str:
    """
    Allow either:
      - "<hex>"
      - "sha256=<hex>"
    """
    sig = (sig or "").strip()
    if sig.lower().startswith("sha256="):
        sig = sig.split("=", 1)[1].strip()
    return sig


def _extract_transfers(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Expect:
    Document -> CstmrCdtTrfInitn -> PmtInf -> CdtTrfTxInf -> [ ... ]
    """
    try:
        return doc["CstmrCdtTrfInitn"]["PmtInf"]["CdtTrfTxInf"]
    except Exception as e:
        raise HTTPException(
            status_code=422,
            detail=f"Missing/invalid ISO20022 path: Document.CstmrCdtTrfInitn.PmtInf.CdtTrfTxInf ({e})"
        )


def _extract_tx_fields(tx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extract and validate per-transaction fields your code needs:
      - amount: float
      - currency: str (upper)
      - reference: str
      - recipient: str
    """
    try:
        instd_amt = tx["Amt"]["InstdAmt"]
        amount_raw = instd_amt["value"]
        currency = str(instd_amt["Ccy"]).upper()
        reference = str(tx["RmtInf"]["Ustrd"])
        recipient = str(tx["Cdtr"]["Nm"])

        # Validate amount
        amount = float(amount_raw)
        if amount <= 0:
            raise ValueError("amount must be > 0")

        # Validate currency
        if not currency:
            raise ValueError("currency is empty")

        return {
            "amount": amount,
            "currency": currency,
            "reference": reference,
            "recipient": recipient,
        }
    except KeyError as e:
        raise HTTPException(status_code=422, detail=f"Missing required field in transaction: {e}")
    except ValueError as e:
        raise HTTPException(status_code=422, detail=f"Invalid value in transaction: {e}")


@app.post("/webhook")
async def receive_webhook(
    request: Request,
    x_fim_signature: str = Header(None),
):
    raw_body = await request.body()

    # ---------------- Signature Verification ----------------
    if VERIFY_SIGNATURE:
        if not SHARED_SECRET:
            # Fail fast if signature verification is enabled but secret isn't set
            raise HTTPException(status_code=500, detail="KAEKSHAREDSECRET not set on server")

        provided_sig = _normalize_signature(x_fim_signature)
        if not provided_sig:
            raise HTTPException(status_code=401, detail="Missing x-fim-signature header")

        expected_sig = _compute_signature(SHARED_SECRET, raw_body)

        # Constant-time compare to avoid subtle timing attacks
        if not hmac.compare_digest(provided_sig, expected_sig):
            logger.warning("Invalid signature detected.")
            raise HTTPException(status_code=401, detail="Invalid signature")

    # ---------------- Parse JSON ----------------
    try:
        data = await request.json()
    except Exception as e:
        logger.error(f"Invalid JSON payload: {e}")
        raise HTTPException(status_code=400, detail="Request body must be valid JSON")

    if not isinstance(data, dict) or "Document" not in data:
        raise HTTPException(status_code=422, detail="Payload must be an object with a top-level 'Document' key")

    document = data["Document"]
    if not isinstance(document, dict):
        raise HTTPException(status_code=422, detail="'Document' must be a JSON object")

    transfers = _extract_transfers(document)
    if not isinstance(transfers, list) or len(transfers) == 0:
        raise HTTPException(status_code=422, detail="CdtTrfTxInf must be a non-empty array")

    logger.info(f"Received {len(transfers)} transaction(s).")

    # ---------------- Process Transactions ----------------
    results = []
    for idx, tx in enumerate(transfers, start=1):
        fields = _extract_tx_fields(tx)
        amount = fields["amount"]
        currency = fields["currency"]
        reference = fields["reference"]
        recipient = fields["recipient"]

        logger.info(f"[{idx}] Ref={reference}, Amount={amount} {currency}, Recipient={recipient}")

        # Record transaction (even if payout fails)
        try:
            record_transaction(reference, recipient, amount, currency)
            logger.info(f"[{idx}] Transaction recorded in database.")
        except Exception as e:
            logger.error(f"[{idx}] Failed to record transaction: {e}")
            # Keep going, but report the DB error
            results.append({
                "reference": reference,
                "recipient": recipient,
                "currency": currency,
                "status": "failed",
                "stage": "database",
                "error": str(e),
            })
            continue

        # Currency filter
        if currency not in SUPPORTED_CURRENCIES:
            logger.warning(f"[{idx}] Unsupported currency: {currency}. Ignored.")
            results.append({
                "reference": reference,
                "recipient": recipient,
                "currency": currency,
                "status": "ignored",
                "reason": f"Unsupported currency: {currency}",
            })
            continue

        # Stripe payout (optional)
        if DISABLE_STRIPE:
            results.append({
                "reference": reference,
                "recipient": recipient,
                "original_currency": currency,
                "status": "recorded_only",
                "note": "Stripe payout disabled (DISABLE_STRIPE=true)",
            })
            continue

        try:
            payout_response = create_stripe_payout(amount, currency)
            results.append({
                "reference": reference,
                "recipient": recipient,
                "original_currency": currency,
                "status": "payout_attempted",
                "payout_result": payout_response,
            })
        except Exception as e:
            logger.error(f"[{idx}] Stripe payout failed: {e}")
            results.append({
                "reference": reference,
                "recipient": recipient,
                "original_currency": currency,
                "status": "failed",
                "stage": "stripe",
                "error": str(e),
            })

    return {"status": "processed", "results": results}

