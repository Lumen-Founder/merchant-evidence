"""Minimal MCP stdio server (JSON-RPC 2.0, newline-delimited) exposing verify_merchant.

Run: python -X utf8 -B -m me.mcp_server <data_dir>   (from merchant_evidence/). SYNTHETIC data in S0.
"""
import json, sys

from .api import EvidenceService
from .core import KeyPair

TOOLS = [{
    "name": "verify_merchant",
    "description": ("Return a signed merchant-evidence attestation for a store domain: on-time delivery, cancellation, "
                    "refund completion/latency, payout accuracy and evidence coverage, computed only from independently "
                    "observed records (grade A/B). Metrics with too few records are INSUFFICIENT_EVIDENCE, not bad."),
    "inputSchema": {"type": "object", "properties": {"domain": {"type": "string"}}, "required": ["domain"]},
}]


def handle(svc, msg):
    mid, method = msg.get("id"), msg.get("method")
    if method == "initialize":
        res = {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
               "serverInfo": {"name": "merchant-evidence", "version": "0.0.1-s0"}}
    elif method == "tools/list":
        res = {"tools": TOOLS}
    elif method == "tools/call":
        p = msg.get("params", {})
        if p.get("name") != "verify_merchant":
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool"}}
        out = svc.verify_merchant(p.get("arguments", {}).get("domain", ""))
        res = {"content": [{"type": "text", "text": json.dumps(out, ensure_ascii=False)}], "isError": False}
    elif method and method.startswith("notifications/"):
        return None
    else:
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": mid, "result": res}


def main():
    data_dir = sys.argv[1]
    svc = EvidenceService(data_dir, KeyPair.from_seed("reg-2026-11", "SYNTHETIC-registry"))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            out = handle(svc, json.loads(line))
        except Exception as e:  # keep server alive on bad input
            out = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": type(e).__name__}}
        if out is not None:
            sys.stdout.write(json.dumps(out, ensure_ascii=False) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
