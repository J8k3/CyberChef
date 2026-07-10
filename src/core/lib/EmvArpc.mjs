/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 *
 * ARPC preimage assembly and parsing for EMV Method 1 and Method 2.
 *
 * Method 1 (Visa, Amex, Discover, JCB):
 *   Preimage = ARQC (8 bytes) || ARC (2 bytes)  →  10 bytes
 *
 * Method 2 (Mastercard M/Chip):
 *   Preimage = ARQC (8 bytes) || CSU (4 bytes) || ProprietaryAuthData (0–8 bytes)  →  12–20 bytes
 */

import OperationError from "../errors/OperationError.mjs";
import { bytesToHex, parseHexBytes } from "./PaymentUtils.mjs";
import { encryptTdesEcb } from "./CardValidationInternals.mjs";
import { generateIso9797Algorithm3Mac } from "./Iso9797.mjs";

const METHOD1 = "Method 1 (Visa/Amex/Discover)";
const METHOD2 = "Method 2 (Mastercard)";
const METHODS = [METHOD1, METHOD2];

const METHOD1_FIELDS = [
    { name: "ARQC",                          bytes: 8, description: "Authorization Request Cryptogram from the card" },
    { name: "ARC",                           bytes: 2, description: "Authorization Response Code (e.g. Y1=5931, Z1=5A31, 00=3030)" },
];

const METHOD2_FIXED_FIELDS = [
    { name: "ARQC",                          bytes: 8, description: "Authorization Request Cryptogram from the card" },
    { name: "Card Status Update (CSU)",      bytes: 4, description: "Issuer response flags (PIN change/unblock, go-online indicators)" },
];

/**
 * @param {string} value
 * @param {string} name
 * @param {number} bytes
 * @returns {string} uppercase hex, validated
 */
function validateHex(value, name, bytes) {
    const h = (value || "").replace(/\s+/g, "").toUpperCase();
    if (!/^[0-9A-F]*$/.test(h))
        throw new OperationError(`${name}: not valid hex.`);
    if (h.length !== bytes * 2)
        throw new OperationError(`${name}: expected ${bytes * 2} hex chars (${bytes} bytes), got ${h.length}.`);
    return h;
}

/**
 * @param {string} value
 * @param {string} name
 * @param {number} maxBytes
 * @returns {string} uppercase hex, validated (may be empty)
 */
function validateOptionalHex(value, name, maxBytes) {
    const h = (value || "").replace(/\s+/g, "").toUpperCase();
    if (h.length === 0) return "";
    if (!/^[0-9A-F]+$/.test(h) || h.length % 2 !== 0)
        throw new OperationError(`${name}: not valid hex.`);
    if (h.length > maxBytes * 2)
        throw new OperationError(`${name}: max ${maxBytes * 2} hex chars (${maxBytes} bytes), got ${h.length}.`);
    return h;
}

/**
 * Build Method 1 preimage.
 * @param {string} arqcHex
 * @param {string} arcHex
 * @returns {{ fields: object[], hex: string }}
 */
function buildMethod1(arqcHex, arcHex) {
    const arqc = validateHex(arqcHex, "ARQC", 8);
    const arc  = validateHex(arcHex, "ARC", 2);
    const fields = [
        { ...METHOD1_FIELDS[0], value: arqc },
        { ...METHOD1_FIELDS[1], value: arc },
    ];
    return { fields, hex: arqc + arc };
}

/**
 * Build Method 2 preimage.
 * @param {string} arqcHex
 * @param {string} csuHex
 * @param {string} padHex  optional, 0–8 bytes
 * @returns {{ fields: object[], hex: string }}
 */
function buildMethod2(arqcHex, csuHex, padHex) {
    const arqc = validateHex(arqcHex, "ARQC", 8);
    const csu  = validateHex(csuHex, "Card Status Update (CSU)", 4);
    const pad  = validateOptionalHex(padHex, "Proprietary Auth Data", 8);
    const fields = [
        { ...METHOD2_FIXED_FIELDS[0], value: arqc },
        { ...METHOD2_FIXED_FIELDS[1], value: csu },
        { name: "Proprietary Auth Data", bytes: pad.length / 2, description: "Optional issuer-specific bytes (0–8)", value: pad },
    ];
    return { fields: pad.length > 0 ? fields : fields.slice(0, 2), hex: arqc + csu + pad };
}

/**
 * Parse Method 1 hex preimage.
 * @param {string} hex
 * @returns {{ fields: object[] }}
 */
function parseMethod1(hex) {
    const h = (hex || "").replace(/\s+/g, "").toUpperCase();
    if (!h || !/^[0-9A-F]+$/.test(h))
        throw new OperationError("Input is not valid hex.");
    if (h.length !== 20)
        throw new OperationError(`Method 1 preimage requires 20 hex chars (10 bytes); got ${h.length}.`);
    return {
        fields: [
            { ...METHOD1_FIELDS[0], value: h.substring(0, 16) },
            { ...METHOD1_FIELDS[1], value: h.substring(16, 20) },
        ]
    };
}

/**
 * Parse Method 2 hex preimage.
 * @param {string} hex
 * @returns {{ fields: object[] }}
 */
function parseMethod2(hex) {
    const h = (hex || "").replace(/\s+/g, "").toUpperCase();
    if (!h || !/^[0-9A-F]+$/.test(h))
        throw new OperationError("Input is not valid hex.");
    if (h.length < 24 || h.length > 40 || h.length % 2 !== 0)
        throw new OperationError(`Method 2 preimage requires 24–40 hex chars (12–20 bytes); got ${h.length}.`);
    const padBytes = (h.length - 24) / 2;
    const fields = [
        { ...METHOD2_FIXED_FIELDS[0], value: h.substring(0, 16) },
        { ...METHOD2_FIXED_FIELDS[1], value: h.substring(16, 24) },
    ];
    if (padBytes > 0)
        fields.push({ name: "Proprietary Auth Data", bytes: padBytes, description: "Optional issuer-specific bytes (0–8)", value: h.substring(24) });
    return { fields };
}

/**
 * Compute a Method 1 ARPC (EMV 4.3 Book 2 §8.2.1).
 *
 *   ARPC = TDES_ECB(SK_AC)[ ARQC XOR (ARC || '00' '00' '00' '00' '00' '00') ]
 *
 * The result is the full 8-byte block. SK_AC is the AC session key (TDES).
 * Verified live against APC verify_auth_request_cryptogram (ArpcMethod1),
 * 2026-07-08.
 *
 * @param {string} preimageHex ARQC(8) || ARC(2), i.e. the Method 1 preimage
 * @param {string} sessionKeyHex TDES session key (16 or 24 bytes)
 * @returns {{ arpcHex: string, arqcHex: string, arcHex: string, blockHex: string }}
 */
function computeArpcMethod1(preimageHex, sessionKeyHex) {
    const { fields } = parseMethod1(preimageHex);
    const arqcHex = fields[0].value;
    const arcHex = fields[1].value;

    const key = parseHexBytes(sessionKeyHex, "Session key", [16, 24]);
    const arqc = parseHexBytes(arqcHex, "ARQC");
    const s = parseHexBytes(`${arcHex}000000000000`, "ARC block"); // ARC || six zero bytes
    const block = new Uint8Array(8);
    for (let i = 0; i < 8; i++) block[i] = arqc[i] ^ s[i];

    const arpc = encryptTdesEcb(key, block);
    return {
        arqcHex,
        arcHex,
        blockHex: bytesToHex(block),
        arpcHex: bytesToHex(arpc),
    };
}

/**
 * Compute a Method 2 ARPC (EMV 4.3 Book 2 §8.2.2).
 *
 *   ARPC = leftmost 4 bytes of MAC_SK_AC( ARQC || CSU || [Proprietary Auth Data] )
 *
 * The MAC is the ISO 9797-1 Algorithm 3 retail MAC over the EMV (ISO 9797-1
 * padding method 2) padded input — matching APC's TDES ARPC. Verified live
 * against APC verify_auth_request_cryptogram (ArpcMethod2), 2026-07-08.
 *
 * @param {string} preimageHex ARQC(8) || CSU(4) || prop(0-8), i.e. the Method 2 preimage
 * @param {string} sessionKeyHex TDES session key (16 or 24 bytes)
 * @returns {{ arpcHex: string, fullMacHex: string }}
 */
function computeArpcMethod2(preimageHex, sessionKeyHex) {
    const { fields } = parseMethod2(preimageHex);
    const preimage = fields.map(f => f.value).join("");
    const mac = generateIso9797Algorithm3Mac(preimage, sessionKeyHex, "Method 2", 4);
    return {
        arpcHex: mac.macHex,
        fullMacHex: mac.fullMacHex,
    };
}

/**
 * Format parsed fields as JSON.
 * @param {object[]} fields
 * @param {string} method
 * @returns {string}
 */
function formatJson(fields, method) {
    const obj = { method };
    for (const f of fields) obj[f.name] = f.value;
    return JSON.stringify(obj, null, 4);
}

/**
 * Format parsed fields as annotated list.
 * @param {object[]} fields
 * @param {string} method
 * @returns {string}
 */
function formatAnnotated(fields, method) {
    const header = `ARPC ${method} preimage\n${"─".repeat(50)}`;
    const rows = fields.map(f =>
        `${f.name.padEnd(30)} ${f.value.padEnd(16)}  [${f.bytes} byte${f.bytes === 1 ? "" : "s"}]`
    );
    return [header, ...rows].join("\n");
}

export {
    METHODS, METHOD1, METHOD2,
    buildMethod1, buildMethod2,
    parseMethod1, parseMethod2,
    computeArpcMethod1, computeArpcMethod2,
    formatJson, formatAnnotated,
};
