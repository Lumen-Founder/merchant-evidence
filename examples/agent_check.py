"""Demo: a buyer agent checks three SYNTHETIC stores before choosing one.

Run from the repository root:  python -X utf8 -B examples/agent_check.py
"""
import os, sys, tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from me.api import EvidenceService  # noqa: E402
from me.core import verify_attestation  # noqa: E402
from me.synthetic import build, save  # noqa: E402


def main():
    reg, keys, ledger, _ = build()
    with tempfile.TemporaryDirectory() as d:
        save(d, reg, ledger)
        svc = EvidenceService(d, keys["registry"])
        pub = svc.registry_public_hex()
        for domain in ["good-store.example", "claims-store.example", "small-store.example", "forger-store.example"]:
            out = svc.verify_merchant(domain)
            if out["status"] != "ATTESTED":
                print(f"{domain:24} {out['status']}")
                continue
            ok, why = verify_attestation(out["attestation"], pub, domain)  # offline check with the registry key
            m = out["attestation"]["metrics"]["on_time_delivery"]
            shown = f"{m['value']:.0%} (n={m['n']}, grades={m['grade_mix']})" if m["status"] == "OK" else f"{m['status']} (n={m['n']})"
            print(f"{domain:24} signature={why:3}  on_time_delivery={shown}")


if __name__ == "__main__":
    main()
