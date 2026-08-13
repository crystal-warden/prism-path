---
name: crypto_agility_cnsa2
start: classify
---

## classify
Route each channel to an approved crypto suite by peer class, data classification, the peer's
capability floor, and the fleet's monotone migration phase. This flow SELECTS a symbolic suite; it
never implements a primitive (the registry binds symbol to provider, `spec-crypto-agility.md` §7).
CUI is adjudicated first and never falls below its floor; every branch below is total via an explicit
catch-all.
-> cui-path: when data_class == "cui"
-> public-path: when peer_class == "public"
-> internal-path: else

## cui-path
Controlled Unclassified Information always takes the highest approved suite, independent of peer or
phase. The class floor made structural: CUI has exactly one reachable outcome.
-> suite-cnsa2-hybrid-1: when always

## public-path
Public peers. Once the fleet is past migration phase 2 the hybrid-PQC suite is mandatory (checked
first, so nothing after it is reachable past the phase floor); before that, capable peers still get
hybrid and only legacy peers fall to classical TLS.
-> suite-tls13-hybrid-x25519mlkem: when migration_phase >= 2
-> suite-tls13-hybrid-x25519mlkem: when hw_floor >= 1
-> suite-tls13-aesgcm: else

## internal-path
Internal peers. Past phase 2 the CNSA-2 hybrid suite is mandatory (checked first); before that,
capable peers get hybrid and legacy peers fall to classical TLS.
-> suite-cnsa2-hybrid-1: when migration_phase >= 2
-> suite-tls13-hybrid-x25519mlkem: when hw_floor >= 1
-> suite-tls13-aesgcm: else

## suite-cnsa2-hybrid-1
Selected suite: CNSA 2.0 hybrid (X25519+ML-KEM-1024 / ML-DSA-87 / AES-256-GCM).
-> end: when always

## suite-tls13-hybrid-x25519mlkem
Selected suite: TLS 1.3 hybrid (X25519+ML-KEM-768 / Ed25519 / ChaCha20-Poly1305).
-> end: when always

## suite-tls13-aesgcm
Selected suite: classical TLS 1.3 (X25519 / Ed25519 / AES-256-GCM). Quantum-vulnerable KEM;
permitted only for public/internal legacy peers before migration phase 2.
-> end: when always

## end
Channel suite selected.
