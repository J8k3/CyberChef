# Payment Operations Reference

Owner:
- Jacob Marks, `https://jacobmarks.com`
- Fork home: `https://github.com/J8k3/CyberChef`

**User-facing workflow catalog, screenshots, and recipe links:** [J8k3/CyberChef-Payments](https://github.com/J8k3/CyberChef-Payments)

This file is the **developer reference** for the implementation repo. It covers naming conventions, the operation registry, and raw APC comparison test data. Do not duplicate recipe catalog content here — maintain it in CyberChef-Payments to avoid divergence.

---

## Naming Convention

All payment operation display names follow **Title Case** throughout. Acronyms (DUKPT, AES, EMV, MAC, PAN, PVV, KCV, ARQC, ARPC, TR-31, TR-34) are always upper-case. Brand names retain their canonical capitalisation (`payShield`).

Pattern: `[Domain Prefix] [Verb] [Qualifier]`
- Domain prefixes: EMV, DUKPT, PIN Block, PIN Data, PIN IBM 3624, PAN, Card Validation Data, VISA PVV, AS2805, HSM, Payment, MAC, Key, TR-31, TR-34
- Verbs: Generate, Verify, Parse, Build, Translate, Derive, Calculate, Encrypt, Decrypt, Re-Encrypt
- The prefix comes first so operations sort and scan by topic in the UI list
- Only operations authored in this fork belong in the Payments category — do not add upstream CyberChef ops

## UI Arrangement

The `Payments` category is sorted alphabetically. The domain-prefix naming convention means related operations naturally cluster together in the list (all EMV ops together, all PIN Block ops together, etc.).

---

## Operation Registry

Operations in the **Payments** category, grouped by domain. Update this list when adding, renaming, or removing an operation.

**Encrypt / Decrypt**
- `Payment Encrypt Data`
- `Payment Decrypt Data`
- `Payment Re-Encrypt Data`

**MAC**
- `MAC Generate`
- `MAC Verify`

**EMV**
- `EMV Build ARQC Data`
- `EMV Parse ARQC Data`
- `EMV Generate ARQC`
- `EMV Verify ARQC`
- `EMV Build ARPC Data`
- `EMV Parse ARPC Data`
- `EMV Generate ARPC`
- `EMV Build Script Data`
- `EMV Build PIN Change Script Data`
- `EMV Generate MAC`
- `EMV Verify MAC`
- `EMV Generate MAC (PIN Change)`
- `EMV Parse TLV`

**Card Validation**
- `Card Validation Data Generate`
- `Card Validation Data Verify`
- `PAN Generate`
- `PAN Parse`

**PIN**
- `PIN Block Build`
- `PIN Block Parse`
- `PIN Block Translate`
- `PIN Block Translate Encrypted`
- `PIN Data Generate`
- `PIN Data Verify`
- `PIN IBM 3624 Offset Generate`
- `PIN IBM 3624 Verify`
- `VISA PVV Generate`
- `VISA PVV Verify`

**DUKPT**
- `DUKPT Derive TDES Key`
- `DUKPT Derive AES Key`

**Key Management**
- `Key Generate`
- `Key Component Split`
- `Key Component Combine`
- `Payment Calculate KCV`
- `Derive ECDH Key Material`
- `AS2805 Generate KEK Validation`

**Key Containers / HSM**
- `TR-31 Parse Key Block`
- `TR-34 Parse Key Transport`
- `HSM Parse Thales Command`
- `HSM Parse Futurex Command`

---

## Spec Grounding

Every payment operation must record **why it is built the way it is** as a structured `Grounding` comment block in the operation's class-level JSDoc. Free-text "Validation:" prose in a description is not sufficient — behavioral claims (padding rules, field encodings, derivation modes) must be forced into `{spec, section}` pairs so they can be checked and challenged. This convention exists because ungrounded prose has already produced real defects: the "Option A/B session-key derivation" description error in this repo (Option A/B are ICC *master-key* derivation modes selected by PAN length — EMV Book 2 Annex A1.4), and the "left-justified, right-padded 0xF" PAN field note that corrupted EMV key derivation in apc-hsm-proxy (MCP KB issue #12).

Grounding lives in **comments, not a runtime field** — nothing in the CyberChef framework consumes a `specGrounding` property, so it would be dead metadata on every operation object. The full format and its hard rules are defined in `AGENTS.md` ("Spec grounding"); the summary:

```js
/**
 * <Operation> operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 * @spec     ISO 9797-1:2011 §7.2
 * @rule     Algorithm 1 is CBC-MAC with the full block cipher on every block, no output transform (TDES per §5).
 * @status   externally-verified
 * @evidence APC generate_mac ISO9797_ALGORITHM1 — apc-crossval 2impl, 2026-07-08.
 */
class GeneratePaymentMAC extends Operation {
```

Status values:

| Status | Meaning |
|---|---|
| `externally-verified` | Behavior confirmed against an independent implementation (APC, published test vector, second reference implementation). `@evidence` is required — name the APC op / vector / date. |
| `cited-unverified` | The spec cite is believed correct but the behavior has not been checked against an independent source. |
| `vendor-convention` | Not a standard — a vendor wire format or HSM convention (e.g. payShield 12-char F-padded offset field). Name the vendor document. |
| `ungrounded` | Behavior exists but no spec cite has been located. A tracked defect, not a durable state — say explicitly what is unresolved, and call it out in the PR. |

Rules of use:

- New payment operations must ship with a `Grounding` block; a PR adding behavior without a grounding entry for it should be rejected.
- When an APC/HSM cross-check validates a rule, upgrade its `@status` in the comment **and** record the evidence in the APC Comparison table below.
- Section numbers must be copied from the document, not recalled from memory. The first grounding pass (2026-07-08) initially cited ISO 9797-1 §7.1/§7.3/§6.1.1 from memory; the actual clauses are §7.2 (Algorithm 1), §7.4 (Algorithm 3), §6.3.2/§6.3.3 (Padding Methods 1/2) — verified against the ISO/IEC 9797-1:2011 text and the EMV 4.1/4.3 Book 2 TOC before correction.
- No `ungrounded` entries currently remain (the last, `EMV Generate ARPC` Method 1, was resolved by implementing the real EMV Book 2 §8.2.1 construction).

---

## APC Comparison Testing

Performed 2026-05-19. HSM-style operations compared against AWS Payment Cryptography (APC) where APC exposed comparable behavior, using fixed test vectors imported as APC managed keys.

### Test Vectors

| Name | Hex |
|---|---|
| `tdes_bdk` | `0123456789ABCDEFFEDCBA9876543210` |
| `aes_bdk` | `FEDCBA98765432100123456789ABCDEF` |
| `tdes_dek1` | `0101010101010101FEFEFEFEFEFEFEFE` |
| `tdes_dek2` | `FEFEFEFEFEFEFEFE0101010101010101` |
| `tdes_m3` | `1111111111111111AAAAAAAAAAAAAAAA` |
| `aes_m6` | `000102030405060708090A0B0C0D0E0F` |
| `visa_pvk` | `AAAABBBBCCCCDDDDEEEEFFFFAAAABBBB` |
| `ibm3624_pvk` | `BBBBCCCCDDDDEEEEFFFFAAAABBBBCCCC` |
| `cvk` | `CCCCDDDDEEEEFFFFAAAABBBBCCCCDDDD` |
| `emv_e0` | `101112131415161718191A1B1C1D1E1F` |
| `tdes_pek` | `DDDDEEEEFFFFAAAABBBBCCCCDDDDEEEE` |
| plaintext | `0102030405060708` |
| mac\_msg | `0102030405060708090A0B0C` |
| pan\_cvv | `4123456789012345` |
| pan\_pvv | `5432101234567890` |
| service\_code | `101` |
| pin | `1234` |
| ksn\_tdes | `FFFF9876543210E00001` |
| ksn\_aes | `123456789012345600000001` |
| atc | `0001` |

### Results

| Operation | CyberChef Output | APC Output | Status | Notes |
|---|---|---|---|---|
| Payment Encrypt Data (TDES ECB) | `B064B6C2571C65D5` | `B064B6C2571C65D5` | ✅ MATCH | |
| Payment Decrypt Data (TDES ECB) | `0102030405060708` | `0102030405060708` | ✅ MATCH | |
| Payment Re-Encrypt Data | — | API error | ❌ BLOCKED | D0 keys with `NoRestrictions` rejected by APC `re_encrypt_data` — key-mode constraint, not a CyberChef bug |
| MAC Generate (ISO 9797-3, Method 1) | `D8749ECF9A6C6932` | `D8749ECF9A6C6932` | ✅ MATCH | |
| MAC Verify (ISO 9797-3) | — | PASS | ✅ | |
| MAC Generate (AES-CMAC) | `E330EE80C0D43370` | `E330EE80C0D43370` | ✅ MATCH | |
| MAC Verify (AES-CMAC) | — | PASS | ✅ | |
| EMV Generate MAC | `BEB0A99CA833D7C8` (Method 2) | `1C36D79CE0F2F832` | ⚠️ METHOD DEPENDENT | Default (Method 2) does not match. Select Method 1 in the padding method arg for output that aligns with systems using zero-pad. |
| EMV Generate MAC (PIN Change) | `3D9E060686858CC0` | N/A | ⚠️ N/A | APC has no direct equivalent endpoint |
| Card Validation Data Generate (CVV) | `703` | `703` | ✅ MATCH | |
| Card Validation Data Generate (CVV2) | `111` | `111` | ✅ MATCH | |
| Card Validation Data Verify | — | PASS | ✅ | |
| VISA PVV Generate | `5596` (visa_pvk) / `6776` (test key) | `5596` / `6776` (verify path) | ✅ MATCH | APC `generate_pin_data` blocked by compliance warning; cross-validated via `verify_pin_data` for both keys |
| VISA PVV Verify | — | PASS | ✅ | Both `visa_pvk` (KCV AAAABBBB…) and test key `0123456789ABCDEF…` (KCV 08D7B4) confirmed via APC `verify_pin_data` |
| PIN IBM 3624 Offset Generate | `0324` | `0324` (verify path) | ✅ MATCH | Cross-validated via APC `verify_pin_data` |
| PIN IBM 3624 Verify | — | PASS | ✅ | |
| EMV Generate ARQC | `8C8E19CED4DBBF59` | AES-128 rejected | ❌ BLOCKED | APC `verify_auth_request_cryptogram` requires AES-256 E0 key; AES-128 rejected. CyberChef computes AES-CMAC over a supplied session key (no derivation in scope) |
| DUKPT Derive TDES Key | IPEK `6AC292FAA1315B4D858AB3A3D7D5933A` | N/A | ✅ VERIFIED | Matches published ANSI X9.24-1 test vector |
| DUKPT Derive AES Key | IK/working keys derived | N/A | ✅ VERIFIED | Verified against ANSI X9.24-3 §6.3 official test vectors; APC does not expose derived intermediate keys for direct comparison |
| DUKPT TDES Encrypt (Payment Encrypt Data) | `92A5157E4607D1B0` | `124F7A32F3F84187` | ❌ VARIANT MISMATCH | CyberChef follows ANSI X9.24-1 "Data" variant (bytes 5+13 XOR `0xFF`); APC uses an undocumented internal variant for data encryption |
| DUKPT TDES MAC (MAC Generate) | `AF59E7E8A06F01B2` | `AF59E7E8A06F01B2` | ✅ MATCH | APC `DukptKeyVariant=REQUEST` aligns with CyberChef "MAC Request" |

### Key Findings

- **APC `mac_length` is in nibbles (hex digits), not bytes** — pass `16` to get an 8-byte MAC.
- **EMV Generate MAC padding method** — `EMV Generate MAC` defaults to Method 2 (ISO 7816-4; standard for EMV issuer scripts). Select Method 1 (zero pad) when the receiving system requires it. Both generate and verify must use the same method.
- **DUKPT TDES data encryption variant** — CyberChef follows ANSI X9.24-1 standard (bytes 5 and 13 XOR `0xFF` for the "Data" variant). APC applies a different undocumented internal variant. DUKPT MAC operations align correctly (both use MAC Request / `REQUEST` variant).
- **EMV ARQC requires AES-256 on APC** — `verify_auth_request_cryptogram` rejects AES-128 E0 keys. If testing ARQC against APC, an AES-256 E0 master key is required. CyberChef's AES-CMAC over a supplied session key follows NIST SP 800-38B; key derivation is out of scope for the op. (An earlier revision of this note called this "Option A session-key derivation" — wrong on both counts: Option A/B are ICC master-key derivation modes selected by PAN length, EMV Book 2 Annex A1.4, and this op derives nothing.)
- **Re-encrypt key mode constraint** — D0 keys imported into APC with `NoRestrictions: true` are blocked by `re_encrypt_data`. This is an APC API constraint, not a CyberChef limitation.

### Corrections — 2026-07-08

Padding-bug audit driven by apc-hsm-proxy findings (proxy issues #19/#21/#42, MCP KB issue #12):

- **ISO 9797-1 Algorithm 1 construction fixed** (`src/core/lib/Iso9797.mjs`). The previous implementation ran single-DES CBC under K1 and then TDES-encrypted the final state — a nonstandard construction matching neither Algorithm 1 (TDES cipher on every block, no output transform; §7.2, and the standard's Introduction: only Algorithms 2, 3, 5, 6 apply a final transformation) nor Algorithm 3. Pre-fix Algorithm 1 outputs (e.g. test vector `0C949BCDEF6FDF1D`) are invalid. Fixed construction verified against an independent TDES-CBC reference (Python `cryptography`); note that for single-block inputs Algorithm 1 and Algorithm 3 coincide, so the new single-block value equals the previously APC-verified Algorithm 3 output. **Live APC cross-check complete (2026-07-08):** an `iso9797_alg1` suite was added to `apc-crossval` (2impl differential, fresh random M1 keys per case, multi-block messages that distinguish Algorithm 1 from Algorithm 3) — all cases match APC `generate_mac` `ISO9797_ALGORITHM1`.
- **Padding Method 1 empty-message case fixed** — an empty message now pads to a single all-zero block per ISO 9797-1:2011 §6.3.2 NOTE 2 (previously produced no blocks at all, so the MAC was computed over nothing). The empty-message MAC equals the key's KCV by construction; the test vector matches the APC-computed KCV `08D7B4` for the test key.
- **IBM 3624 verify accepts F-padded offsets** — `PIN IBM 3624 Verify` now strips trailing `F` fill so the fixed 12-character payShield offset field can be pasted directly (mirror of apc-hsm-proxy issue #21).
- The DUKPT TDES data-encryption variant mismatch (issue #20) is unchanged: CyberChef remains standard-correct per ANSI X9.24-1; APC applies an undocumented internal variant.

### Live 2impl validation round — 2026-07-08 (apc-crossval)

Full `apc-crossval` run against live APC (fresh random keys per case, keys deleted on every exit path): **all suites PASS** — CVV, AES-CMAC, HMAC-SHA256, ISO 9797-1 Algorithm 3, **ISO 9797-1 Algorithm 1 (new suite — validates the construction fix above)**, Visa PVV, IBM 3624 offset, EMV ARQC (Option A + EMV Common SK from-spec derivation feeding CyberChef's Algorithm 3 MAC).

A full implementation cross-check against the live-validated `apc-hsm-proxy` handlers found the shared primitives in agreement (PVV, CVV, IBM 3624 incl. F-strip, PIN blocks 0/1/3, DUKPT TDES/AES derivation, issuer-script MAC primitive) and surfaced three gaps.

**Fixed 2026-07-08 — ARPC wrong output.** `EMV Generate ARPC` previously computed `AES-CMAC(ARQC||ARC)` for every method — wrong for both. It is now method-aware and matches EMV Book 2 exactly, verified live against APC `verify_auth_request_cryptogram`:
- **Method 1** (§8.2.1): `ARPC = TDES(SK)[ARQC ⊕ (ARC || six zero bytes)]`, full 8-byte block.
- **Method 2** (§8.2.2): leftmost 4 bytes of the ISO 9797-1 Algorithm 3 retail MAC over the method-2-padded `ARQC || CSU || proprietary` data.

Both are covered by a new `apc-crossval` `arpc` suite (2impl differential, fresh random keys, both methods, proprietary data present and absent) — all cases match APC. The op's arg signature changed: the old `[key, cryptogramBytes, outputJson]` became `[key, method, outputJson]` (output length is fixed by the method: 8 bytes for Method 1, 4 for Method 2). `EMV Build ARPC Data` is unchanged — its Method 1 preimage `ARQC||ARC` is now consumed correctly as the two structured inputs rather than MAC'd.

**Remaining gaps (tracked):**
1. **Single-DES (8-byte key) ISO 9797-1 Algorithm 1** (ANSI X9.9 legacy, accepted by payShield MA/MC and APC) is rejected by CyberChef's 16/24-byte key validation — errors out rather than mis-computing, but cannot reproduce legacy X9.9 MACs.
2. **ISO Format 4 (AES) PIN blocks** unsupported (existing issue #18); the proxy handles Thales format code '48' → APC IsoFormat4.

---

### References

- AWS Payment Cryptography Data Plane API: https://docs.aws.amazon.com/payment-cryptography/latest/DataAPIReference/Welcome.html
- AWS MAC overview: https://docs.aws.amazon.com/payment-cryptography/latest/userguide/crypto-ops-mac.html
- NIST SP 800-38B CMAC: https://csrc.nist.gov/pubs/sp/800/38/b/upd1/final
- RFC 3394 AES Key Wrap: https://www.rfc-editor.org/rfc/rfc3394
- Discover public test-card page: https://www.discoverglobalnetwork.com/resources/businesses/check-your-card-reader/
- Mastercard AVS test scenarios: https://static.developer.mastercard.com/content/mastercard-send-avs/uploads/avs-test-case-scenario-v4.pdf
