## Top-5 Risk Register

1. Ledger too complex
    Mitigation: implement permissioned hash-chained append-only log; single service; no consensus

2. Crypto misuse/bugs
    Mitigation: use PyNaCl / cryptography; keep protocol minimal; add unit tests for each primitive

3. Revocation ambiguity
    Mitigation: revoke transaction; “latest record wins”; verify active before handshake

4. Replay attacks not handled
    Mitigation: per-device monotonic sequence numbers; reject duplicate/old seq; bounded cache

5. Integration/demo failures
    Mitigation: modularize (registry / session / telemetry); scripted demo; fallback to localhost only