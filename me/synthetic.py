"""SYNTHETIC fixtures for S0 tests and demos. Not real merchants, carriers or orders."""
import json, random
from datetime import datetime, timedelta, timezone

from .core import IssuerRegistry, KeyPair, Ledger, ingest, make_record, order_ref

FMT = "%Y-%m-%dT%H:%M:%SZ"


def ts(dt):
    return dt.strftime(FMT)


def build(seed=7, start="2026-09-01T00:00:00Z"):
    rng = random.Random(seed)
    reg = IssuerRegistry()
    keys = {
        "registry": KeyPair.from_seed("reg-2026-11", "SYNTHETIC-registry"),
        "platform": KeyPair.from_seed("platform-demo", "SYNTHETIC-platform"),
        "m_good": KeyPair.from_seed("merchant-good", "SYNTHETIC-m-good"),
        "m_claim": KeyPair.from_seed("merchant-claim", "SYNTHETIC-m-claim"),
        "m_forger": KeyPair.from_seed("merchant-forger", "SYNTHETIC-m-forger"),
    }
    reg.add(keys["registry"], "registry")
    reg.add(keys["platform"], "platform")
    reg.add(keys["m_good"], "merchant:good-store.example")
    reg.add(keys["m_claim"], "merchant:claims-store.example")
    reg.add(keys["m_forger"], "merchant:forger-store.example")
    ledger, seen, log = Ledger(), set(), []
    t0 = datetime.strptime(start, FMT).replace(tzinfo=timezone.utc)

    def put(rec):
        ok, g, why = ingest(ledger, reg, rec, seen)
        log.append({"merchant": rec["merchant_domain"], "event": rec["event_type"], "accepted": ok, "grade": g, "reason": why})

    # good-store: 120 orders, carrier deliveries observed by registry (A), platform orders (B)
    for i in range(120):
        o = order_ref("good-store", f"G{i}", "salt-g")
        placed = t0 + timedelta(hours=rng.randint(0, 24 * 50))
        promised = placed + timedelta(days=5)
        put(make_record(keys["registry"], "good-store.example", o, "order_placed", ts(placed), "platform", "registry",
                        {"promised_delivery_by": ts(promised)}, f"platform-order-{i}".encode()))
        if rng.random() < 0.03:
            put(make_record(keys["registry"], "good-store.example", o, "cancelled", ts(placed + timedelta(hours=3)),
                            "platform", "registry", {"reason": "customer_request"}, f"cancel-{i}".encode()))
            continue
        late = rng.random() < 0.06
        dl = placed + timedelta(days=rng.randint(6, 8) if late else rng.randint(2, 5))
        put(make_record(keys["registry"], "good-store.example", o, "delivered", ts(dl), "carrier", "registry",
                        {}, f"carrier-scan-{i}".encode()))
        if rng.random() < 0.35:
            rq = dl + timedelta(days=rng.randint(1, 10))
            put(make_record(keys["registry"], "good-store.example", o, "refund_requested", ts(rq), "platform", "registry",
                            {"amount_minor": 2500, "currency": "USD"}, f"refund-req-{i}".encode()))
            put(make_record(keys["registry"], "good-store.example", o, "refund_paid", ts(rq + timedelta(days=rng.randint(1, 4))),
                            "payment_processor", "registry", {"amount_minor": 2500, "currency": "USD"}, f"refund-paid-{i}".encode()))
        amt = rng.randint(1000, 9000)
        put(make_record(keys["registry"], "good-store.example", o, "payout_expected", ts(dl + timedelta(days=2)), "platform",
                        "registry", {"amount_minor": amt, "currency": "USD"}, f"payout-exp-{i}".encode()))
        put(make_record(keys["registry"], "good-store.example", o, "payout_received", ts(dl + timedelta(days=3)),
                        "payment_processor", "registry", {"amount_minor": amt if rng.random() > 0.02 else amt - 150, "currency": "USD"},
                        f"payout-rcv-{i}".encode()))
    # claims-store: only self-claims (D) and merchant files (C)
    for i in range(80):
        o = order_ref("claims-store", f"C{i}", "salt-c")
        placed = t0 + timedelta(hours=rng.randint(0, 24 * 50))
        put(make_record(keys["m_claim"], "claims-store.example", o, "delivered", ts(placed + timedelta(days=2)),
                        "merchant_claim", "merchant", {"note": "we always ship on time"}, f"claim-{i}".encode()))
        put(make_record(keys["m_claim"], "claims-store.example", o, "order_placed", ts(placed),
                        "merchant_file", "merchant", {"promised_delivery_by": ts(placed + timedelta(days=5))}, f"csv-{i}".encode()))
    # forger-store: merchant key claiming to be a carrier -> rejected
    for i in range(40):
        o = order_ref("forger-store", f"F{i}", "salt-f")
        placed = t0 + timedelta(hours=rng.randint(0, 24 * 50))
        put(make_record(keys["m_forger"], "forger-store.example", o, "delivered", ts(placed + timedelta(days=1)),
                        "carrier", "registry", {}, f"fake-scan-{i}".encode()))
    # small-store: 12 orders, A/B evidence but too few
    for i in range(12):
        o = order_ref("small-store", f"S{i}", "salt-s")
        placed = t0 + timedelta(hours=rng.randint(0, 24 * 50))
        put(make_record(keys["registry"], "small-store.example", o, "order_placed", ts(placed), "platform", "registry",
                        {"promised_delivery_by": ts(placed + timedelta(days=5))}, f"s-order-{i}".encode()))
        put(make_record(keys["registry"], "small-store.example", o, "delivered", ts(placed + timedelta(days=3)), "carrier",
                        "registry", {}, f"s-scan-{i}".encode()))
    return reg, keys, ledger, log


def save(dirpath, reg, ledger):
    import os
    os.makedirs(dirpath, exist_ok=True)
    json.dump(reg.keys, open(os.path.join(dirpath, "issuers.json"), "w", encoding="utf-8"), indent=1)
    ledger.dump(os.path.join(dirpath, "ledger.jsonl"))
