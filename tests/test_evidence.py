import copy, json, os, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from me import ed25519  # noqa: E402
from me.core import (IssuerRegistry, KeyPair, Ledger, grade, ingest, issue_attestation, make_record,  # noqa: E402
                     order_ref, verify_attestation, canon)
from me.synthetic import build, save  # noqa: E402
from me.api import EvidenceService  # noqa: E402

P = ("2026-09-01T00:00:00Z", "2026-11-01T00:00:00Z")


def test_rfc8032_vector1():
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = ed25519.public_key(sk)
    assert pk.hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    sig = ed25519.sign(sk, b"")
    assert sig.hex() == ("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bac"
                         "c61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ed25519.verify(pk, b"", sig)
    assert not ed25519.verify(pk, b"x", sig)


def _world():
    return build()


def test_grades_and_rejections():
    reg, keys, ledger, log = _world()
    by = {}
    for r in log:
        by.setdefault((r["merchant"], r["reason"]), 0)
        by[(r["merchant"], r["reason"])] += 1
    # forger: merchant key claiming carrier -> rejected, never in ledger
    assert by[("forger-store.example", "source_mismatch_merchant_key_claims_carrier")] == 40
    assert not any(e["record"]["merchant_domain"] == "forger-store.example" for e in ledger.entries)
    # claims-store: D (claims) and C (files) accepted into ledger but graded low
    assert by[("claims-store.example", "merchant_claim")] == 80
    assert by[("claims-store.example", "merchant_file")] == 80


def test_forged_signature_rejected():
    reg, keys, ledger, _ = _world()
    rec = copy.deepcopy(ledger.entries[0]["record"])
    rec["payload"]["promised_delivery_by"] = "2030-01-01T00:00:00Z"  # tamper after signing
    g, why = grade(rec, reg)
    assert g is None and why == "bad_signature"


def test_unknown_key_rejected():
    reg, keys, ledger, _ = _world()
    rogue = KeyPair.from_seed("rogue", "SYNTHETIC-rogue")
    rec = make_record(rogue, "good-store.example", "x", "delivered", "2026-09-10T00:00:00Z", "carrier", "registry", {}, b"r")
    assert grade(rec, reg) == (None, "unknown_key")


def test_foreign_merchant_key_rejected():
    reg, keys, ledger, _ = _world()
    rec = make_record(keys["m_good"], "claims-store.example", "x", "order_placed", "2026-09-10T00:00:00Z",
                      "merchant_file", "merchant", {}, b"r")
    assert grade(rec, reg) == (None, "foreign_merchant_key")


def test_duplicate_rejected():
    reg, keys, ledger, _ = _world()
    seen = {e["record"]["record_id"] for e in ledger.entries}
    rec = ledger.entries[5]["record"]
    ok, g, why = ingest(ledger, reg, rec, seen)
    assert not ok and why == "duplicate"


def test_ledger_tamper_detected():
    reg, keys, ledger, _ = _world()
    assert ledger.verify_chain() == (True, None)
    ledger.entries[10]["record"]["event_time"] = "2026-09-02T00:00:00Z"
    ok, at = ledger.verify_chain()
    assert not ok and at == 10


def test_metrics_only_from_A_B_and_insufficient():
    reg, keys, ledger, _ = _world()
    from me.core import compute_metrics
    good = compute_metrics(ledger, reg, "good-store.example", *P)
    assert good["on_time_delivery"]["status"] == "OK" and 0.85 <= good["on_time_delivery"]["value"] <= 1.0
    assert set(good["on_time_delivery"]["grade_mix"]) == {"A"}
    claims = compute_metrics(ledger, reg, "claims-store.example", *P)
    assert claims["on_time_delivery"]["status"] == "INSUFFICIENT_EVIDENCE" and claims["on_time_delivery"]["n"] == 0
    assert claims["merchant_reported_records_excluded"] == 80
    small = compute_metrics(ledger, reg, "small-store.example", *P)
    assert small["on_time_delivery"]["status"] == "INSUFFICIENT_EVIDENCE" and small["on_time_delivery"]["n"] == 12


def test_attestation_verify_expiry_reuse_and_head():
    reg, keys, ledger, _ = _world()
    att = issue_attestation(keys["registry"], ledger, reg, "good-store.example", *P)
    pub = keys["registry"].public.hex()
    assert verify_attestation(att, pub, "good-store.example", ledger_head=ledger.head()) == (True, "ok")
    assert verify_attestation(att, pub, "other-store.example")[1] == "domain_mismatch"  # reuse by another merchant
    assert verify_attestation(att, pub, "good-store.example", now="2099-01-01T00:00:00Z")[1] == "expired"
    assert verify_attestation(att, pub, "good-store.example", ledger_head="f" * 64)[1] == "ledger_head_mismatch"
    forged = copy.deepcopy(att)
    forged["metrics"]["on_time_delivery"]["value"] = 1.0
    assert verify_attestation(forged, pub, "good-store.example")[1] == "bad_signature"
    other = KeyPair.from_seed("evil-registry", "SYNTHETIC-evil")
    assert verify_attestation(att, other.public.hex(), "good-store.example")[1] == "bad_signature"


def test_attestation_refuses_broken_ledger():
    reg, keys, ledger, _ = _world()
    ledger.entries[3]["prev_hash"] = "0" * 64
    try:
        issue_attestation(keys["registry"], ledger, reg, "good-store.example", *P)
        assert False
    except ValueError:
        pass


def test_service_and_mcp_roundtrip(tmp_path):
    reg, keys, ledger, _ = _world()
    save(str(tmp_path), reg, ledger)
    svc = EvidenceService(str(tmp_path), keys["registry"])
    out = svc.verify_merchant("good-store.example")
    assert out["status"] == "ATTESTED" and out["self_check"]["ok"]
    assert svc.verify_merchant("unknown.example")["status"] == "NO_EVIDENCE_ON_RECORD"
    reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "verify_merchant", "arguments": {"domain": "good-store.example"}}}]
    proc = subprocess.run([sys.executable, "-X", "utf8", "-B", "-m", "me.mcp_server", str(tmp_path)], cwd=ROOT,
                          input="\n".join(json.dumps(r) for r in reqs) + "\n", capture_output=True, text=True, timeout=600)
    lines = [json.loads(l) for l in proc.stdout.splitlines() if l.strip()]
    assert [l["id"] for l in lines] == [1, 2, 3]
    assert lines[1]["result"]["tools"][0]["name"] == "verify_merchant"
    payload = json.loads(lines[2]["result"]["content"][0]["text"])
    assert payload["status"] == "ATTESTED" and payload["self_check"]["ok"]
