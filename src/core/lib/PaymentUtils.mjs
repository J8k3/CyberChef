/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import OperationError from "../errors/OperationError.mjs";
import { toHexFast } from "./Hex.mjs";

/**
 * Parses hex into bytes.
 *
 * @param {string} input
 * @param {string} name
 * @param {number[]} [allowedLengths]
 * @returns {Uint8Array}
 */
function parseHexBytes(input, name, allowedLengths=[]) {
    const normalized = (input || "").replace(/\s+/g, "");
    if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
        throw new OperationError(`${name} must be hex.`);
    }

    // Validate the declared length before allocating, so an oversized input is
    // rejected without allocating a buffer for it.
    if (allowedLengths.length && !allowedLengths.includes(normalized.length / 2)) {
        throw new OperationError(`${name} must be ${allowedLengths.join(" or ")} bytes.`);
    }

    const out = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < out.length; i++) {
        out[i] = parseInt(normalized.substring(i * 2, i * 2 + 2), 16);
    }

    return out;
}


/**
 * Fills a Uint8Array of `length` bytes from the platform CSPRNG.
 *
 * Throws rather than silently falling back to a non-cryptographic source: any
 * caller here generates key material, nonces, or fill for security-relevant
 * values, so a missing CSPRNG must fail loudly, never degrade to Math.random().
 *
 * @param {number} length
 * @returns {Uint8Array}
 */
function secureRandomBytes(length) {
    if (!(globalThis.crypto && typeof globalThis.crypto.getRandomValues === "function")) {
        throw new OperationError("A secure random number generator (crypto.getRandomValues) is not available in this environment.");
    }
    const out = new Uint8Array(length);
    globalThis.crypto.getRandomValues(out);
    return out;
}


/**
 * Returns a uniformly-distributed integer in [0, maxExclusive) from the CSPRNG,
 * using rejection sampling to avoid the modulo bias of `rand % maxExclusive`.
 *
 * @param {number} maxExclusive positive integer up to 2**32
 * @returns {number}
 */
function secureRandomInt(maxExclusive) {
    if (!Number.isInteger(maxExclusive) || maxExclusive < 1 || maxExclusive > 0x100000000) {
        throw new OperationError("secureRandomInt bound must be an integer in 1..2**32.");
    }
    if (maxExclusive === 1) return 0;
    // Largest multiple of maxExclusive that fits in 32 bits; draws at or above it
    // are rejected so the remaining range maps evenly onto [0, maxExclusive).
    const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
    for (;;) {
        const buf = secureRandomBytes(4);
        const value = ((buf[0] * 0x1000000) + (buf[1] << 16) + (buf[2] << 8) + buf[3]);
        if (value < limit) return value % maxExclusive;
    }
}


/**
 * Converts bytes to uppercase hex.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function bytesToHex(bytes) {
    return toHexFast(bytes).toUpperCase();
}


/**
 * XORs two equal-length byte arrays, returning a new Uint8Array.
 *
 * @param {Uint8Array} left
 * @param {Uint8Array} right
 * @returns {Uint8Array}
 */
function xorBytes(left, right) {
    const out = new Uint8Array(left.length);
    for (let i = 0; i < left.length; i++) {
        out[i] = left[i] ^ right[i];
    }
    return out;
}


/**
 * Normalizes and validates a PAN (12–19 decimal digits, whitespace stripped).
 *
 * @param {string} pan
 * @returns {string}
 */
function normalizePan(pan) {
    const normalized = (pan || "").replace(/\s+/g, "");
    if (!/^\d{12,19}$/.test(normalized)) {
        throw new OperationError("PAN must be 12 to 19 digits.");
    }
    return normalized;
}


/**
 * Normalizes and validates a clear PIN (4–12 decimal digits, whitespace stripped).
 *
 * @param {string} pin
 * @returns {string}
 */
function normalizePin(pin) {
    const normalized = (pin || "").replace(/\s+/g, "");
    if (!/^\d{4,12}$/.test(normalized)) {
        throw new OperationError("PIN must be 4 to 12 digits.");
    }
    return normalized;
}


/**
 * Converts bytes to a forge-compatible byte string.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
function toByteString(bytes) {
    return Array.from(bytes, byte => String.fromCharCode(byte)).join("");
}


/**
 * Converts hex to an ArrayBuffer.
 *
 * @param {string} input
 * @param {string} name
 * @returns {ArrayBuffer}
 */
function parseHexBuffer(input, name) {
    const bytes = parseHexBytes(input, name);
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}


export {
    bytesToHex,
    normalizePan,
    normalizePin,
    parseHexBuffer,
    parseHexBytes,
    secureRandomBytes,
    secureRandomInt,
    toByteString,
    xorBytes,
};
