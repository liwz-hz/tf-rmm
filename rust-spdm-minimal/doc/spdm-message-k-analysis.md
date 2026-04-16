# SPDM message_k Transcript Analysis

## Key Discovery (2026-04-16)

This document records critical findings from debugging FINISH HMAC verification failure.

## C Library Analysis Results

**C library version passes FINISH verification successfully!**

### Responder Internal Flow (libspdm_rsp_key_exchange.c)

```
Line 566: append KE_req to message_k
Line 574: append KE_rsp_no_sig to message_k  <-- message_k used for signature
Line 582: generate signature using TH_for_exchange = message_a + cert_chain_hash + message_k
Line 591: append signature to message_k       <-- message_k now = req + rsp_no_sig + sig
Line 601: calculate TH1 from message_k         <-- TH1 used for key derivation
Line 610: generate handshake keys
Line 624: generate HMAC using response_finished_key
Line 633: append HMAC to message_k             <-- message_k now = req + rsp_no_sig + sig + hmac
```

### TH Calculation Functions

Both `libspdm_calculate_th_for_exchange` and `libspdm_calculate_th_for_finish` use the same structure:
```
TH = message_a + cert_chain_hash + message_k
```

**The difference is WHEN they are called:**

| Function | Call Timing | message_k Contents |
|----------|------------|-------------------|
| TH_for_exchange (signature) | After line 574 | KE_req + KE_rsp_no_sig |
| TH1 (key derivation) | After line 591 | KE_req + KE_rsp_no_sig + signature |
| TH_curr (FINISH) | After line 633 | KE_req + KE_rsp_no_sig + signature + HMAC |

### Network Packet vs Internal Transcript

**Responder sends**: 246 bytes = KE_rsp_no_sig + signature (NO HMAC in network packet)

**Responder internal message_k**: Contains HMAC (calculated but not sent)

**Requester must**: Calculate the same HMAC and append to its message_k

### Key Derivation Order

From responder debug output:
```
th_curr hash  <-- used for signature (before signature appended)
th1 hash      <-- used for key derivation (after signature appended)
finished_key (request) <-- from request_handshake_secret
finished_key (response) <-- from response_handshake_secret
th_curr hmac  <-- KEY_EXCHANGE_RSP HMAC (using response_finished_key + TH1)
```

### Requester HMAC Calculation

Requester must calculate responder's HMAC:
1. Derive `response_handshake_secret` from `handshake_secret` using bin_str2
2. Derive `response_finished_key` from `response_handshake_secret` using bin_str7
3. Calculate `HMAC(response_finished_key, TH1_hash)`
4. Append this HMAC to message_k
5. Calculate TH_curr = Hash(message_a + cert_chain_hash + message_k + FINISH_req_header)
6. Calculate verify_data = HMAC(request_finished_key, TH_curr_hash)

### bin_str Definitions

```
bin_str1 = "spdm1.2 req hs data" + TH1 → request_handshake_secret
bin_str2 = "spdm1.2 rsp hs data" + TH1 → response_handshake_secret
bin_str7 = "spdm1.2 finished" → finished_key (both req and rsp)
```

### Transcript Size Analysis

```
message_a: 160 bytes (VERSION 4+16 + CAPABILITIES 20+20 + ALGORITHMS 48+48 + DIGESTS 4+? + CERTIFICATE chunks)
cert_chain_hash: 48 bytes (SHA-384 hash of complete cert_chain including SPDM header)
message_k: 
  - KE_req: 154 bytes
  - KE_rsp_no_sig: 150 bytes (Header 4 + session_id 2 + mut_auth 1 + slot_id 1 + random 32 + dhe 96 + opaque_len 2 + opaque 12)
  - signature: 96 bytes (ECDSA-P384)
  - HMAC: 48 bytes (SHA-384)
FINISH_req_header: 4 bytes
```

## The Fix

1. **TH1**: message_a + cert_chain_hash + message_k (req + rsp_no_sig + signature) - **NO HMAC**
2. **TH_curr**: message_a + cert_chain_hash + message_k (req + rsp_no_sig + signature + HMAC) + FINISH_header
3. **Responder HMAC**: HMAC(response_finished_key, TH1_hash) - NOT TH_curr!

### Critical Insight

Responder's HMAC for KEY_EXCHANGE_RSP uses **TH1_hash** as input, NOT the full transcript!
This is verified in `libspdm_generate_key_exchange_rsp_hmac` line 45-65:
- It calls `libspdm_calculate_th_for_exchange` (which gives TH without HMAC)
- Then hashes that TH to get TH1_hash
- Then computes HMAC(response_finished_key, TH1_hash)

## libspdm Source References

- `ext/libspdm/library/spdm_responder_lib/libspdm_rsp_key_exchange.c` lines 566-633
- `ext/libspdm/library/spdm_requester_lib/libspdm_req_key_exchange.c` lines 721-805
- `ext/libspdm/library/spdm_common_lib/libspdm_com_crypto_service_session.c`:
  - `libspdm_calculate_th_for_exchange` (lines 22-94)
  - `libspdm_calculate_th_for_finish` (lines 219-290)
- `ext/libspdm/library/spdm_responder_lib/libspdm_rsp_finish.c` lines 12-79 (HMAC generation)