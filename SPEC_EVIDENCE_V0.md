# Merchant Evidence spec v0 (draft, 2026-11-08)

Goal: record a merchant's real transactions (orders, deliveries, cancellations, refunds, payouts) as **source evidence**, prove provenance and integrity, and let buyer agents verify it mechanically. This is not a rating system. Each metric stands alone; there is no composite score.

Status: S0 prototype, synthetic data only. Signatures use the RFC 8032 Ed25519 reference algorithm in pure Python; production must use an audited library.

## 1. Evidence grades — the more independent of the merchant's own word, the higher

| Grade | Source (`source.kind`) | Observer (`source.observer`) | Used for metrics |
|---|---|---|---|
| A | carrier, payment_processor, marketplace | `registry` (fetched by the registry from the source of record) or signed by the source itself | yes |
| B | platform (certified transaction records of a commerce platform) | `registry`, through a merchant-approved read-only connection | yes |
| C | merchant_file (settlement files, internal records submitted by the merchant) | merchant | shown separately as merchant-reported |
| D | merchant_claim (self-reported statements, marketing copy) | merchant | **never** |

The grade is re-derived by the verifier from source, observer and signing key; nothing self-declared is trusted. A record signed with a merchant key that claims to be a carrier record is rejected (`source_mismatch`).

## 2. Evidence record

```json
{
  "schema": "merchant-evidence/v0",
  "record_id": "uuid",
  "merchant_domain": "example-store.com",
  "order_ref": "sha256(merchant id | order number | secret salt)",
  "event_type": "order_placed | shipped | delivered | cancelled | refund_requested | refund_paid | payout_expected | payout_received",
  "event_time": "ISO-8601 UTC",
  "observed_time": "ISO-8601 UTC",
  "source": {"kind": "carrier", "issuer_id": "registry", "observer": "registry"},
  "payload": {"promised_delivery_by": "...", "amount_minor": 0, "currency": "USD", "reason": "..."},
  "raw_sha256": "hash of the original source document (stored separately)",
  "signature": {"alg": "ed25519", "key_id": "...", "sig": "hex"}
}
```

No customer personal data. Orders are referenced only by salted hashes. Source documents and derived results are stored separately.

## 3. Ledger

Append-only JSONL: `{seq, prev_hash, record, entry_hash}`. Each entry hashes the previous one, so changing any entry breaks every later hash.

## 4. Metrics (grade A/B records only)

| Metric | Definition |
|---|---|
| on_time_delivery | delivered by the promised date / delivered orders |
| cancellation_rate | cancelled / placed |
| refund_latency_days | median days from refund_requested to refund_paid |
| refund_completion | refund_paid / refund_requested |
| payout_accuracy | payout_received with matching amount / payout_expected |
| evidence_coverage | orders with A/B delivery evidence / placed orders |

A metric with fewer records than the minimum (default 30) is `INSUFFICIENT_EVIDENCE`: missing evidence, not a bad merchant.

## 5. Attestation

Signed by the registry key: period, per-metric value / sample size / grade mix, coverage, ledger head hash, issue time, expiry (default 30 days). An agent verifies the signature with the registry public key and checks domain, expiry and (optionally) the ledger head.

## 6. Lookup

`verify_merchant(domain)` returns the signed attestation and a self-check. The same function is exposed as an MCP tool (stdio JSON-RPC: initialize, tools/list, tools/call). A UCP extension would follow reverse-domain naming (`com.<reversed domain>.shopping.merchant_evidence`); the name is not fixed yet.

## 7. Data rights (built into the product)

1. Explicit written consent per merchant before connecting.
2. Read-only connections wherever possible.
3. No customer personal data.
4. Not used as AI training data.
5. Disconnect and deletion: after deletion no attestation is issued for that merchant.
6. Source documents and derived attestations stored separately.

## 8. Failure cases covered by the tests

Forged signature, unknown key, foreign merchant key, duplicate record, ledger tampering, expired attestation, source mismatch, grade D exclusion, insufficient sample, reuse of another merchant's attestation, wrong registry key, refusal to attest a broken ledger.
