# merchant-evidence

**Pre-D1 prototype. Synthetic data only. Not a rating service.**

Merchant Evidence Infrastructure: record a merchant's real transactions (orders, deliveries, cancellations, refunds, payouts) as source evidence, prove provenance and integrity, and let buyer agents verify it mechanically. Not a rating product: metrics are separate, there is no composite score, and too few records gives `INSUFFICIENT_EVIDENCE`, never a low score.

- Spec: `SPEC_EVIDENCE_V0.md`. Demo: `python -X utf8 -B examples/agent_check.py`. Evidence grades: A = carrier / payment processor / marketplace record, observed by the registry or signed by the source. B = platform record read through a merchant-approved read-only connection. C = merchant files (shown separately). D = merchant claims (never used).
- `me/ed25519.py`: RFC 8032 reference Ed25519 in pure Python. Prototype only: not constant-time. Use an audited library in production.
- `me/core.py`: records, issuer registry, grade re-derivation, hash-chained ledger, metrics, signed attestations, agent-side verification.
- `me/api.py`: `verify_merchant(domain)`.
- `me/mcp_server.py`: minimal MCP stdio server exposing `verify_merchant`.
- `me/synthetic.py`: synthetic fixtures (good store, claims-only store, forger store, small store).
- `tests/test_evidence.py`: RFC 8032 vector, forged signature, unknown key, foreign merchant key, duplicate, ledger tamper, A/B-only metrics, insufficient sample, attestation expiry / reuse / head mismatch / wrong registry key, broken-ledger refusal, MCP round trip.

Run tests (from this folder):

```
python -X utf8 -B -m pytest -q -p no:cacheprovider tests
```

Status: pre-D1 prototype. No real merchant data, no deployment, no network calls.
