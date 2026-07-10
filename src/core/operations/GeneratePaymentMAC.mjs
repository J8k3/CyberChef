/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { ISO9797_PADDING_METHODS, PAYMENT_MAC_METHODS, generatePaymentMac } from "../lib/PaymentMac.mjs";

/**
 * Generate payment MAC operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     ISO 9797-1:2011 — §7.2
 * @rule     Algorithm 1 is CBC-MAC with the full block cipher applied to every block and no output transformation (Introduction: only Algorithms 2, 3, 5, 6 apply a final transformation); with a TDES key the cipher is TDES, since §5 restricts DEA to Algorithms 3 and 4.
 * @status   externally-verified
 * @evidence apc-crossval 2impl differential vs APC generate_mac ISO9797_ALGORITHM1, 2026-07-08: multi-block cases (8/16/24/32 bytes, fresh random keys) all match. Clause text verified against ISO/IEC 9797-1:2011; independent TDES-CBC reference (Python cryptography)
 *
 * @spec     ISO 9797-1:2011 — §7.4
 * @rule     Algorithm 3 (retail MAC): single-DES CBC-MAC under K1 with final output transformation E(K1)[D(K2)[state]].
 * @status   externally-verified
 * @evidence APC comparison 2026-05-19 (ISO9797_ALGORITHM3 MATCH)
 *
 * @spec     ISO 9797-1:2011 — §6.3.2 / §6.3.3
 * @rule     Padding Method 1 right-pads with zeros to a positive multiple of the block size (§6.3.2 NOTE 2: an empty message pads to one all-zero block); Method 2 appends a '1' bit (0x80) then zero-pads.
 * @status   externally-verified
 * @evidence Clause text verified against ISO/IEC 9797-1:2011 (iTeh preview, 2026-07-08); empty-message MAC equals the key's APC-computed KCV (08D7B4), test vector in Payment.mjs
 *
 * @spec     AS2805.4.1 — MAC generation
 * @rule     AS2805-4.1 MAC equals the ISO 9797-1 Algorithm 3 retail MAC (zero padding by default).
 * @status   cited-unverified
 *
 * @spec     ANSI X9.24-1 — §7.5
 * @rule     DUKPT methods derive the transaction MAC key from the BDK/KSN using the MAC Request or MAC Response variant before MACing.
 * @status   externally-verified
 * @evidence APC comparison 2026-05-19 (DukptKeyVariant=REQUEST MATCH); IPEK matches published X9.24-1 test vector
 */
class GeneratePaymentMAC extends Operation {

    /**
     * GeneratePaymentMAC constructor.
     */
    constructor() {
        super();

        this.name = "MAC Generate";
        this.module = "Payment";
        this.description = "Paste the message data into the input field and generate a payment-oriented MAC using one payment-facing operation.<br><br><b>Input:</b> message data in the selected input format.<br><b>Arguments:</b> choose the MAC method, provide either a direct key or a DUKPT BDK, optionally provide a KSN for DUKPT methods, choose the ISO9797 padding rule when applicable, and choose the truncation length.<br><br><b>Validation:</b> Mixed. HMAC/CMAC rely on established primitives. ISO9797 / AS2805 and DUKPT modes are software-emulation helpers that need to be interpreted in the scope called out by each method and key context.<br><br><b>Security:</b> Uses clear key material in the recipe. Do not paste production keys into shared or untrusted environments.";
        this.inlineHelp = "<strong>Input:</strong> message data.<br><strong>Args:</strong> choose the payment MAC method, then provide either a direct key or a DUKPT BDK plus KSN.<br><strong>Validation:</strong> primitive-backed for HMAC/CMAC; broader payment semantics are profile-specific.";
        this.testDataSamples = [
            {
                name: "Static AES-CMAC sample",
                input: "1122334455667788",
                args: ["Hex", "AES-CMAC", "00112233445566778899AABBCCDDEEFF", "Hex", "", "Method 1", 8, false]
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/Message_authentication_code";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Input format",
                type: "option",
                value: ["Hex", "UTF8", "Latin1", "Base64"],
                comment: "How to decode the input field before MAC generation. Use <code>Hex</code> for payment test vectors expressed as hex."
            },
            {
                name: "MAC method",
                type: "option",
                value: PAYMENT_MAC_METHODS,
                comment: "Static-key HMAC and CMAC modes reuse the existing generic primitives. ISO9797 and AS2805 modes apply TDES-based payment MAC logic. DUKPT modes derive a TDES session key first. Note: ISO 9797-1 Algorithm 1 and Algorithm 3 are legacy MAC profiles — prefer AES-CMAC for new implementations."
            },
            {
                name: "Key / BDK",
                type: "string",
                value: "",
                comment: "Provide the direct MAC key for HMAC or CMAC methods, or the clear BDK for DUKPT methods."
            },
            {
                name: "Key format",
                type: "option",
                value: ["Hex", "UTF8", "Latin1", "Base64"],
                comment: "How to decode the key input. Assumption: DUKPT BDK input must be <code>Hex</code>."
            },
            {
                name: "KSN (DUKPT only)",
                type: "string",
                value: "",
                comment: "Required only for DUKPT MAC methods. Provide the full 10-byte KSN as 20 hex characters."
            },
            {
                name: "ISO9797 padding",
                type: "option",
                value: ISO9797_PADDING_METHODS,
                comment: "Used only for ISO9797 and AS2805 MAC methods. <code>Method 1</code> pads with zero bytes to the next block. <code>Method 2</code> appends <code>80</code> then zeros."
            },
            {
                name: "Output bytes",
                type: "number",
                value: 8,
                min: 1,
                max: 64,
                comment: "Number of leftmost MAC bytes to return. Leave at <code>8</code> for common payment truncation lengths."
            },
            {
                name: "Output as JSON",
                type: "boolean",
                value: false,
                comment: "When enabled, returns the full MAC, truncation details, and key-context metadata."
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [inputFormat, method, keyValue, keyFormat, ksn, paddingMethod, outputBytes, outputJson] = args;
        const result = generatePaymentMac(input, inputFormat, method, keyValue, keyFormat, ksn, outputBytes, paddingMethod);
        return outputJson ? JSON.stringify(result, null, 4) : result.macHex;
    }
}

export default GeneratePaymentMAC;
