from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import uuid
from datetime import UTC, date, datetime

LICENSE_KEY_PREFIX = "THP1"


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(raw: str) -> bytes:
    padded = raw + ("=" * ((4 - len(raw) % 4) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def license_signing_secret() -> str:
    return os.environ.get("THERATRAK_LICENSE_SECRET", "THERATRAK-PRO-LICENSE-CHANGE-THIS")


def current_machine_code() -> str:
    source = "|".join([
        os.environ.get("COMPUTERNAME", "").strip().upper(),
        hex(uuid.getnode()),
        os.environ.get("PROCESSOR_IDENTIFIER", "").strip().upper(),
    ])
    return hashlib.sha256(source.encode("utf-8")).hexdigest()[:16].upper()


def build_license_key(name: str, email: str, machine_code: str = "", expires: str = "") -> str:
    payload = {
        "v": 1,
        "n": (name or "").strip(),
        "e": (email or "").strip().lower(),
        "mc": (machine_code or "").strip().upper(),
        "exp": (expires or "").strip(),
        "iat": datetime.now(UTC).strftime("%Y-%m-%d"),
    }
    payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = hmac.new(license_signing_secret().encode("utf-8"), payload_raw, hashlib.sha256).digest()[:16]
    return f"{LICENSE_KEY_PREFIX}.{b64u_encode(payload_raw)}.{b64u_encode(sig)}"


def validate_license_key(license_key: str, machine_code: str) -> tuple[bool, str, dict[str, str]]:
    normalized = re.sub(r"\s+", "", str(license_key or "").strip())
    parts = normalized.split(".")
    if len(parts) != 3 or parts[0] != LICENSE_KEY_PREFIX:
        return False, "License key format is invalid.", {}

    try:
        payload_raw = b64u_decode(parts[1])
        sig = b64u_decode(parts[2])
    except Exception:
        return False, "License key payload could not be decoded.", {}

    expected = hmac.new(license_signing_secret().encode("utf-8"), payload_raw, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(sig, expected):
        return False, "License key signature is invalid.", {}

    try:
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception:
        return False, "License key data is unreadable.", {}

    if not isinstance(payload, dict):
        return False, "License key payload is invalid.", {}

    key_machine = str(payload.get("mc") or "").strip().upper()
    if key_machine and key_machine != machine_code.strip().upper():
        return False, "This license key is for a different machine.", {}

    exp_text = str(payload.get("exp") or "").strip()
    if exp_text:
        try:
            exp_date = datetime.strptime(exp_text, "%Y-%m-%d").date()
        except ValueError:
            return False, "Invalid expiration date in key.", {}
        if date.today() > exp_date:
            return False, "This license key has expired.", {}

    return True, "License key is valid.", {
        "name": str(payload.get("n") or "").strip(),
        "email": str(payload.get("e") or "").strip(),
        "machine": key_machine,
        "expires": exp_text,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate and verify TheraTrak Pro license keys.")
    parser.add_argument("--name", help="Customer or practice name.")
    parser.add_argument("--email", help="Customer email.")
    parser.add_argument("--machine", default="", help="Machine code from customer app (optional).")
    parser.add_argument("--expires", default="", help="Expiration date YYYY-MM-DD (optional).")
    parser.add_argument("--verify", default="", help="License key to verify.")
    parser.add_argument("--show-machine", action="store_true", help="Print this machine's code.")
    args = parser.parse_args()

    if args.show_machine:
        print(current_machine_code())

    if args.verify:
        check_machine = (args.machine or current_machine_code()).strip().upper()
        ok, msg, data = validate_license_key(args.verify, check_machine)
        print(msg)
        if data:
            print(json.dumps(data, indent=2))
        return 0 if ok else 1

    if not args.name or not args.email:
        parser.error("--name and --email are required when generating a key.")

    if args.expires:
        try:
            datetime.strptime(args.expires, "%Y-%m-%d")
        except ValueError:
            parser.error("--expires must be in YYYY-MM-DD format.")

    key = build_license_key(args.name, args.email, args.machine, args.expires)
    print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
