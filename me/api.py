"""verify_merchant service over a ledger directory (issuers.json + ledger.jsonl)."""
import json, os

from .core import IssuerRegistry, KeyPair, Ledger, issue_attestation, verify_attestation


class EvidenceService:
    def __init__(self, data_dir: str, registry_kp: KeyPair, period=("2026-09-01T00:00:00Z", "2026-11-01T00:00:00Z")):
        self.reg = IssuerRegistry()
        self.reg.keys = json.load(open(os.path.join(data_dir, "issuers.json"), encoding="utf-8"))
        self.ledger = Ledger.load(os.path.join(data_dir, "ledger.jsonl"))
        self.kp = registry_kp
        self.period = period

    def registry_public_hex(self):
        return self.kp.public.hex()

    def known_domains(self):
        return sorted({e["record"]["merchant_domain"] for e in self.ledger.entries})

    def verify_merchant(self, domain: str) -> dict:
        domain = (domain or "").strip().lower()
        if domain not in self.known_domains():
            return {"merchant_domain": domain, "status": "NO_EVIDENCE_ON_RECORD",
                    "note": "No verified transaction evidence. This is not a negative rating."}
        att = issue_attestation(self.kp, self.ledger, self.reg, domain, *self.period)
        ok, why = verify_attestation(att, self.registry_public_hex(), domain, ledger_head=self.ledger.head())
        return {"merchant_domain": domain, "status": "ATTESTED", "attestation": att,
                "registry_public_key_hex": self.registry_public_hex(), "self_check": {"ok": ok, "reason": why}}
