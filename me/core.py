"""Merchant Evidence v0 core: records, issuer registry, grading, ledger, metrics, attestations.

Spec: ../SPEC_EVIDENCE_V0_KO.md. No customer PII; orders referenced by salted hashes only.
"""
import hashlib, json, statistics, uuid
from datetime import datetime, timedelta, timezone

from . import ed25519

SCHEMA = "merchant-evidence/v0"
ATT_SCHEMA = "merchant-attestation/v0"
EVENT_TYPES = {"order_placed", "shipped", "delivered", "cancelled", "refund_requested", "refund_paid",
               "payout_expected", "payout_received"}
GRADE_A_KINDS = {"carrier", "payment_processor", "marketplace"}
MIN_SAMPLE = 30


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def order_ref(merchant_id: str, order_no: str, salt: str) -> str:
    return sha256_hex(f"{merchant_id}|{order_no}|{salt}".encode())


class KeyPair:
    def __init__(self, key_id: str, secret: bytes):
        self.key_id, self.secret = key_id, secret
        self.public = ed25519.public_key(secret)

    @classmethod
    def from_seed(cls, key_id: str, seed: str):
        return cls(key_id, hashlib.sha256(seed.encode()).digest())


class IssuerRegistry:
    """key_id -> {public_hex, role}. role: registry | carrier | payment_processor | marketplace | platform | merchant:<domain>"""

    def __init__(self):
        self.keys = {}

    def add(self, kp: KeyPair, role: str):
        self.keys[kp.key_id] = {"public_hex": kp.public.hex(), "role": role}

    def role(self, key_id):
        return self.keys.get(key_id, {}).get("role")

    def public(self, key_id):
        k = self.keys.get(key_id)
        return bytes.fromhex(k["public_hex"]) if k else None


def unsigned_view(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "signature"}


def make_record(kp: KeyPair, merchant_domain, oref, event_type, event_time, kind, observer, payload, raw_doc: bytes):
    if event_type not in EVENT_TYPES:
        raise ValueError("unknown event_type")
    rec = {"schema": SCHEMA, "record_id": str(uuid.uuid4()), "merchant_domain": merchant_domain, "order_ref": oref,
           "event_type": event_type, "event_time": event_time, "observed_time": now_iso(),
           "source": {"kind": kind, "issuer_id": kp.key_id, "observer": observer},
           "payload": payload, "raw_sha256": sha256_hex(raw_doc)}
    rec["signature"] = {"alg": "ed25519", "key_id": kp.key_id, "sig": ed25519.sign(kp.secret, canon(rec)).hex()}
    return rec


def grade(rec: dict, reg: IssuerRegistry):
    """Return (grade or None, reason). Grade is re-derived; nothing self-declared is trusted."""
    sig = rec.get("signature") or {}
    key_id = sig.get("key_id")
    pub = reg.public(key_id)
    if rec.get("schema") != SCHEMA:
        return None, "bad_schema"
    if pub is None:
        return None, "unknown_key"
    try:
        ok = ed25519.verify(pub, canon(unsigned_view(rec)), bytes.fromhex(sig.get("sig", "")))
    except ValueError:
        ok = False
    if not ok:
        return None, "bad_signature"
    role = reg.role(key_id)
    src = rec.get("source", {})
    kind, observer = src.get("kind"), src.get("observer")
    if src.get("issuer_id") != key_id:
        return None, "issuer_mismatch"
    if role.startswith("merchant:"):
        if role.split(":", 1)[1] != rec.get("merchant_domain"):
            return None, "foreign_merchant_key"
        if kind == "merchant_file":
            return "C", "merchant_file"
        if kind == "merchant_claim":
            return "D", "merchant_claim"
        return None, "source_mismatch_merchant_key_claims_" + str(kind)
    if role == "registry":
        if observer != "registry":
            return None, "observer_mismatch"
        if kind in GRADE_A_KINDS:
            return "A", "registry_observed_source_of_record"
        if kind == "platform":
            return "B", "registry_observed_platform"
        return None, "registry_bad_kind"
    if role in GRADE_A_KINDS and kind == role:
        return "A", "source_signed"
    if role == "platform" and kind == "platform":
        return "B", "platform_signed"
    return None, "source_mismatch"


class Ledger:
    def __init__(self):
        self.entries = []

    def head(self):
        return self.entries[-1]["entry_hash"] if self.entries else "0" * 64

    def append(self, rec: dict):
        e = {"seq": len(self.entries), "prev_hash": self.head(), "record": rec}
        e["entry_hash"] = sha256_hex(canon(e))
        self.entries.append(e)
        return e

    def verify_chain(self):
        prev = "0" * 64
        for i, e in enumerate(self.entries):
            body = {"seq": e["seq"], "prev_hash": e["prev_hash"], "record": e["record"]}
            if e["seq"] != i or e["prev_hash"] != prev or sha256_hex(canon(body)) != e["entry_hash"]:
                return False, i
            prev = e["entry_hash"]
        return True, None

    def dump(self, path):
        with open(path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path):
        lg = cls()
        with open(path, encoding="utf-8") as f:
            lg.entries = [json.loads(l) for l in f if l.strip()]
        return lg


def ingest(ledger: Ledger, reg: IssuerRegistry, rec: dict, seen: set):
    """Validate one record; append if acceptable. Returns (accepted, grade, reason)."""
    g, why = grade(rec, reg)
    if g is None:
        return False, None, why
    key = (rec["merchant_domain"], rec["order_ref"], rec["event_type"], rec["raw_sha256"])
    if rec["record_id"] in seen or key in seen:
        return False, g, "duplicate"
    seen.add(rec["record_id"]); seen.add(key)
    ledger.append(rec)
    return True, g, why


def _metric(num, den, grades, min_sample):
    if den < min_sample:
        return {"status": "INSUFFICIENT_EVIDENCE", "n": den, "grade_mix": grades}
    return {"status": "OK", "value": round(num / den, 4), "n": den, "grade_mix": grades}


def compute_metrics(ledger: Ledger, reg: IssuerRegistry, domain: str, since: str, until: str, min_sample=MIN_SAMPLE):
    s, u = parse(since), parse(until)
    ev = {}
    merchant_reported = 0
    for e in ledger.entries:
        r = e["record"]
        if r["merchant_domain"] != domain or not (s <= parse(r["event_time"]) < u):
            continue
        g, _ = grade(r, reg)
        if g in ("C",):
            merchant_reported += 1
        if g not in ("A", "B"):
            continue
        ev.setdefault(r["order_ref"], {}).setdefault(r["event_type"], []).append((r, g))

    def mix(pairs):
        m = {}
        for _, g in pairs:
            m[g] = m.get(g, 0) + 1
        return m

    placed = [o for o in ev.values() if "order_placed" in o]
    delivered = [o for o in ev.values() if "delivered" in o]
    on_time = 0
    dmix = []
    for o in delivered:
        r, g = o["delivered"][0]
        dmix.append((r, g))
        by = (o.get("order_placed") or o["delivered"])[0][0]["payload"].get("promised_delivery_by")
        if by and parse(r["event_time"]) <= parse(by):
            on_time += 1
    cancelled = [o for o in placed if "cancelled" in o]
    reqs = [o for o in ev.values() if "refund_requested" in o]
    paid = [o for o in reqs if "refund_paid" in o]
    lat = [(parse(o["refund_paid"][0][0]["event_time"]) - parse(o["refund_requested"][0][0]["event_time"])).total_seconds() / 86400 for o in paid]
    pexp = [o for o in ev.values() if "payout_expected" in o]
    pmatch = [o for o in pexp if "payout_received" in o and
              o["payout_received"][0][0]["payload"].get("amount_minor") == o["payout_expected"][0][0]["payload"].get("amount_minor")]
    out = {
        "on_time_delivery": _metric(on_time, len(delivered), mix(dmix), min_sample),
        "cancellation_rate": _metric(len(cancelled), len(placed), mix([p for o in placed for p in o["order_placed"]]), min_sample),
        "refund_completion": _metric(len(paid), len(reqs), mix([p for o in reqs for p in o["refund_requested"]]), min_sample),
        "payout_accuracy": _metric(len(pmatch), len(pexp), mix([p for o in pexp for p in o["payout_expected"]]), min_sample),
        "evidence_coverage": _metric(len(delivered), len(placed), {}, min_sample),
    }
    out["refund_latency_days"] = ({"status": "OK", "median": round(statistics.median(lat), 2), "n": len(lat)}
                                  if len(lat) >= min_sample else {"status": "INSUFFICIENT_EVIDENCE", "n": len(lat)})
    out["merchant_reported_records_excluded"] = merchant_reported
    return out


def issue_attestation(reg_kp: KeyPair, ledger: Ledger, reg: IssuerRegistry, domain, since, until, ttl_days=30):
    ok, bad = ledger.verify_chain()
    if not ok:
        raise ValueError(f"ledger chain broken at {bad}")
    att = {"schema": ATT_SCHEMA, "merchant_domain": domain, "period": {"since": since, "until": until},
           "metrics": compute_metrics(ledger, reg, domain, since, until), "ledger_head": ledger.head(),
           "issued_at": now_iso(),
           "expires_at": (datetime.now(timezone.utc) + timedelta(days=ttl_days)).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "method": "SPEC_EVIDENCE_V0: metrics from grade A/B only; C excluded and counted; D never used",
           "issuer": reg_kp.key_id}
    att["signature"] = {"alg": "ed25519", "key_id": reg_kp.key_id, "sig": ed25519.sign(reg_kp.secret, canon(att)).hex()}
    return att


def verify_attestation(att: dict, registry_public_hex: str, domain: str, now: str = None, ledger_head: str = None):
    """Agent-side check. Returns (ok, reason)."""
    if att.get("schema") != ATT_SCHEMA:
        return False, "bad_schema"
    if att.get("merchant_domain") != domain:
        return False, "domain_mismatch"
    body = {k: v for k, v in att.items() if k != "signature"}
    try:
        ok = ed25519.verify(bytes.fromhex(registry_public_hex), canon(body), bytes.fromhex(att["signature"]["sig"]))
    except (ValueError, KeyError):
        ok = False
    if not ok:
        return False, "bad_signature"
    if parse(now or now_iso()) >= parse(att["expires_at"]):
        return False, "expired"
    if ledger_head is not None and ledger_head != att["ledger_head"]:
        return False, "ledger_head_mismatch"
    return True, "ok"
