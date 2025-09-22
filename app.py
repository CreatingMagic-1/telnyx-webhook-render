import os, time, json, base64
from flask import Flask, request, Response, jsonify
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

TELNYX_PUBLIC_KEY = os.environ.get("TELNYX_PUBLIC_KEY", "").strip()  # ED25519 public key from Telnyx
MAX_SKEW_SEC = int(os.environ.get("MAX_SKEW_SEC", "300"))            # 5 minutes

app = Flask(__name__)

def verify_telnyx_signature(raw_body: bytes, timestamp: str, signature_b64: str) -> bool:
    # Require key
    if not TELNYX_PUBLIC_KEY:
        return False
    # Replay protection
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > MAX_SKEW_SEC:
            return False
    except Exception:
        return False

    message = f"{timestamp}|".encode() + raw_body

    # Public key may be hex or base64. Try hex, then base64.
    try:
        verify_key = VerifyKey(bytes.fromhex(TELNYX_PUBLIC_KEY))
    except Exception:
        try:
            verify_key = VerifyKey(base64.b64decode(TELNYX_PUBLIC_KEY))
        except Exception:
            return False

    try:
        signature = base64.b64decode(signature_b64)
        verify_key.verify(message, signature)
        return True
    except (BadSignatureError, Exception):
        return False

@app.route("/telnyx", methods=["POST"])
def telnyx_webhook():
    raw = request.get_data()  # RAW body for signature check
    ts = request.headers.get("telnyx-timestamp", "")
    sig = request.headers.get("telnyx-signature-ed25519", "")

    if not verify_telnyx_signature(raw, ts, sig):
        return Response("invalid signature", status=400)

    # Parse JSON for logging
    try:
        event = json.loads(raw.decode("utf-8"))
    except Exception:
        event = {"raw": raw.decode("utf-8", "ignore")}

    print(json.dumps({"received_at": int(time.time()), "event": event})[:4000])
    return Response("ok", status=200)

@app.route("/health", methods=["GET"])
def health():
    ok = bool(TELNYX_PUBLIC_KEY)
    return jsonify({"ok": ok, "has_public_key": ok}), (200 if ok else 500)

@app.route("/", methods=["GET"])
def root():
    return "Telnyx webhook is live. POST /telnyx  •  GET /health", 200
