/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";
import { METHODS, METHOD1, computeArpcMethod1, computeArpcMethod2 } from "../lib/EmvArpc.mjs";

/**
 * Generate EMV ARPC operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     EMV 4.3 Book 2 — §8.2.1 (ARPC Method 1)
 * @rule     ARPC = TDES(SK_AC)[ARQC XOR (ARC || '00' '00' '00' '00' '00' '00')] — the full 8-byte block. Not a MAC over ARQC||ARC.
 * @status   externally-verified
 * @evidence apc-crossval probe vs APC verify_auth_request_cryptogram ArpcMethod1, 2026-07-08: TDES(SK)[ARQC^(ARC||0*6)] matches APC AuthResponseValue byte-for-byte
 *
 * @spec     EMV 4.3 Book 2 — §8.2.2 (ARPC Method 2)
 * @rule     ARPC = leftmost 4 bytes of the ISO 9797-1 Algorithm 3 retail MAC over the EMV (ISO 9797-1 method 2) padded ARQC || CSU || proprietary data.
 * @status   externally-verified
 * @evidence apc-crossval probe vs APC verify_auth_request_cryptogram ArpcMethod2, 2026-07-08: Alg3(SK, method2-pad(ARQC||CSU||prop)) leftmost 4 matches APC AuthResponseValue
 */
class GenerateEMVARPC extends Operation {

    /**
     * GenerateEMVARPC constructor.
     */
    constructor() {
        super();

        this.name = "EMV Generate ARPC";
        this.module = "Payment";
        this.description = "Paste the preassembled ARPC input data (from <b>EMV Build ARPC Data</b>) into the input field as hex and generate the ARPC used for issuer authentication.<br><br><b>Input:</b> preassembled ARPC preimage as hex — Method 1 is <code>ARQC(8) || ARC(2)</code>; Method 2 is <code>ARQC(8) || CSU(4) || proprietary(0-8)</code>.<br><b>Arguments:</b> provide the TDES AC session key in hex and select the ARPC method.<br><br><b>Method 1</b> (Visa, Amex, Discover, JCB): <code>ARPC = TDES(SK)[ARQC XOR (ARC || six zero bytes)]</code> — an 8-byte block, EMV Book 2 §8.2.1.<br><b>Method 2</b> (Mastercard M/Chip): <code>ARPC = leftmost 4 bytes of the ISO 9797-1 Algorithm 3 retail MAC over the ARPC data</code>, EMV Book 2 §8.2.2.<br><br><b>Validation:</b> Both methods verified live against AWS Payment Cryptography <code>verify_auth_request_cryptogram</code> (ArpcMethod1 / ArpcMethod2) on 2026-07-08.<br><br><b>Session key derivation:</b> The AC session key is derived from the issuer master key (same key used for ARQC verification) — see <b>EMV Generate ARQC</b>. This operation expects the already-derived session key and the assembled preimage.<br><br><b>Security:</b> Clear session keys are test-use only.";
        this.inlineHelp = "<strong>Input:</strong> preassembled ARPC data as hex (from EMV Build ARPC Data).<br><strong>Args:</strong> provide the TDES AC session key and select the ARPC method.<br><strong>Method 1</strong> returns 8 bytes; <strong>Method 2</strong> returns 4 bytes.";
        this.testDataSamples = [
            {
                name: "ARPC Method 1 (TDES XOR-encrypt)",
                input: "82ACC80D7EAA12BB3030",
                args: ["5BBFD4C7755611D6F5BC7A7FE16E23ED", METHOD1, false]
            },
            {
                name: "ARPC Method 2 (Retail MAC, 4 bytes)",
                input: "82ACC80D7EAA12BB00000000",
                args: ["5BBFD4C7755611D6F5BC7A7FE16E23ED", "Method 2 (Mastercard)", false]
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/EMV";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "AC session key (hex)",
                type: "string",
                value: "",
                comment: "Provide the already-derived TDES AC session key as hex (16 or 24 bytes). This op does not derive EMV session keys."
            },
            {
                name: "ARPC method",
                type: "option",
                value: METHODS,
                comment: "Method 1 (Visa/Amex/Discover): TDES XOR-encrypt, 8-byte ARPC. Method 2 (Mastercard): Retail-MAC, 4-byte ARPC. Must match the method used in EMV Build ARPC Data."
            },
            {
                name: "Output as JSON",
                type: "boolean",
                value: false,
                comment: "When enabled, returns the intermediate values (XOR block / full MAC) alongside the ARPC."
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [sessionKeyHex, method, outputJson] = args;
        const normalizedInput = (input || "").replace(/\s+/g, "").toUpperCase();

        let result;
        if (method === METHOD1) {
            result = { method, ...computeArpcMethod1(normalizedInput, sessionKeyHex) };
        } else if (METHODS.includes(method)) {
            result = { method, ...computeArpcMethod2(normalizedInput, sessionKeyHex) };
        } else {
            throw new OperationError("Unknown ARPC method.");
        }

        return outputJson ? JSON.stringify(result, null, 4) : result.arpcHex;
    }
}

export default GenerateEMVARPC;
