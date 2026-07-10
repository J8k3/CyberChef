/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import forge from "node-forge";
import OperationError from "../errors/OperationError.mjs";
import { bytesToHex, parseHexBytes, toByteString, xorBytes } from "./PaymentUtils.mjs";

const ISO9797_PADDING_METHODS = ["Method 1", "Method 2"];

/**
 * Pads input according to ISO/IEC 9797-1 padding method 1 or 2.
 *
 * @param {Uint8Array} data
 * @param {number} blockSize
 * @param {string} paddingMethod
 * @returns {Uint8Array}
 */
function applyIso9797Padding(data, blockSize, paddingMethod) {
    if (!ISO9797_PADDING_METHODS.includes(paddingMethod)) {
        throw new OperationError("Unsupported ISO9797 padding method.");
    }

    if (paddingMethod === "Method 1") {
        // ISO 9797-1:2011 §6.3.2 NOTE 2: "If the data string is empty, Padding
        // Method 1 specifies that it is right-padded with n '0' bits."
        if (data.length === 0) return new Uint8Array(blockSize);
        const remainder = data.length % blockSize;
        if (remainder === 0) return Uint8Array.from(data);
        const out = new Uint8Array(data.length + (blockSize - remainder));
        out.set(data, 0);
        return out;
    }

    const remainder = data.length % blockSize;
    const extra = remainder === 0 ? blockSize : blockSize - remainder;
    const out = new Uint8Array(data.length + extra);
    out.set(data, 0);
    out[data.length] = 0x80;
    return out;
}

/**
 * Encrypts one 8-byte block with DES ECB.
 *
 * @param {Uint8Array} key8
 * @param {Uint8Array} block8
 * @returns {Uint8Array}
 */
function encryptDesBlock(key8, block8) {
    const cipher = forge.cipher.createCipher("DES-ECB", toByteString(key8));
    cipher.mode.pad = function() {
        return true;
    };
    cipher.start();
    cipher.update(forge.util.createBuffer(toByteString(block8)));
    cipher.finish();
    return Uint8Array.from(cipher.output.getBytes().split("").map(ch => ch.charCodeAt(0))).slice(0, 8);
}

/**
 * Decrypts one 8-byte block with DES ECB.
 *
 * @param {Uint8Array} key8
 * @param {Uint8Array} block8
 * @returns {Uint8Array}
 */
function decryptDesBlock(key8, block8) {
    const decipher = forge.cipher.createDecipher("DES-ECB", toByteString(key8));
    decipher.mode.unpad = function() {
        return true;
    };
    decipher.start();
    decipher.update(forge.util.createBuffer(toByteString(block8)));
    decipher.finish();
    return Uint8Array.from(decipher.output.getBytes().split("").map(ch => ch.charCodeAt(0))).slice(0, 8);
}

/**
 * Encrypts one 8-byte block with TDES ECB.
 *
 * @param {Uint8Array} key
 * @param {Uint8Array} block8
 * @returns {Uint8Array}
 */
function encryptTdesBlock(key, block8) {
    const normalizedKey = key.length === 16 ? Uint8Array.from([...key, ...key.slice(0, 8)]) : key;
    const cipher = forge.cipher.createCipher("3DES-ECB", toByteString(normalizedKey));
    cipher.mode.pad = function() {
        return true;
    };
    cipher.start();
    cipher.update(forge.util.createBuffer(toByteString(block8)));
    cipher.finish();
    return Uint8Array.from(cipher.output.getBytes().split("").map(ch => ch.charCodeAt(0))).slice(0, 8);
}

/**
 * Encrypts blocks with DES CBC-MAC style chaining.
 *
 * @param {Uint8Array} key8
 * @param {Uint8Array} padded
 * @returns {Uint8Array}
 */
function runDesCbcMac(key8, padded) {
    let state = new Uint8Array(8);
    for (let i = 0; i < padded.length; i += 8) {
        const block = padded.slice(i, i + 8);
        state = encryptDesBlock(key8, xorBytes(state, block));
    }
    return state;
}

/**
 * Encrypts blocks with TDES CBC-MAC chaining (ISO 9797-1 Algorithm 1 with a
 * TDES block cipher: every block through the full cipher, no output transform).
 *
 * @param {Uint8Array} key
 * @param {Uint8Array} padded
 * @returns {Uint8Array}
 */
function runTdesCbcMac(key, padded) {
    let state = new Uint8Array(8);
    for (let i = 0; i < padded.length; i += 8) {
        const block = padded.slice(i, i + 8);
        state = encryptTdesBlock(key, xorBytes(state, block));
    }
    return state;
}

/**
 * Normalizes a MAC key for ISO9797-style MACs.
 *
 * @param {string} keyHex
 * @returns {Uint8Array}
 */
function normalizeIso9797Key(keyHex) {
    return parseHexBytes(keyHex, "MAC key", [16, 24]);
}

/**
 * Generates an ISO9797 algorithm 1 MAC.
 *
 * @param {string} inputHex
 * @param {string} keyHex
 * @param {string} paddingMethod
 * @param {number} outputBytes
 * @returns {Object}
 */
function generateIso9797Algorithm1Mac(inputHex, keyHex, paddingMethod, outputBytes=8) {
    const data = parseHexBytes(inputHex, "Input data");
    const key = normalizeIso9797Key(keyHex);
    const padded = applyIso9797Padding(data, 8, paddingMethod);
    const fullMacBytes = runTdesCbcMac(key, padded);
    const fullMacHex = bytesToHex(fullMacBytes);
    const macHex = fullMacHex.substring(0, Math.max(1, Math.min(8, Number(outputBytes) || 8)) * 2);

    return {
        algorithm: "ISO 9797-1 Algorithm 1",
        paddingMethod,
        inputHex: bytesToHex(data),
        fullMacHex,
        macHex,
    };
}

/**
 * Generates an ISO9797 algorithm 3 retail MAC.
 *
 * @param {string} inputHex
 * @param {string} keyHex
 * @param {string} paddingMethod
 * @param {number} outputBytes
 * @returns {Object}
 */
function generateIso9797Algorithm3Mac(inputHex, keyHex, paddingMethod, outputBytes=8) {
    const data = parseHexBytes(inputHex, "Input data");
    const key = normalizeIso9797Key(keyHex);
    const padded = applyIso9797Padding(data, 8, paddingMethod);
    const key1 = key.slice(0, 8);
    const key2 = key.slice(8, 16);
    const key3 = key.length === 24 ? key.slice(16, 24) : key1;
    const cbcState = runDesCbcMac(key1, padded);
    const fullMacBytes = encryptDesBlock(key3, decryptDesBlock(key2, cbcState));
    const fullMacHex = bytesToHex(fullMacBytes);
    const macHex = fullMacHex.substring(0, Math.max(1, Math.min(8, Number(outputBytes) || 8)) * 2);

    return {
        algorithm: "ISO 9797-1 Algorithm 3",
        paddingMethod,
        inputHex: bytesToHex(data),
        fullMacHex,
        macHex,
    };
}

/**
 * Generates an AS2805 4.1 MAC.
 *
 * @param {string} inputHex
 * @param {string} keyHex
 * @param {string} paddingMethod
 * @param {number} outputBytes
 * @returns {Object}
 */
function generateAs2805Mac(inputHex, keyHex, paddingMethod="Method 1", outputBytes=8) {
    const retail = generateIso9797Algorithm3Mac(inputHex, keyHex, paddingMethod, outputBytes);
    return {
        ...retail,
        algorithm: "AS2805-4.1"
    };
}

export {
    ISO9797_PADDING_METHODS,
    generateAs2805Mac,
    generateIso9797Algorithm1Mac,
    generateIso9797Algorithm3Mac,
};
