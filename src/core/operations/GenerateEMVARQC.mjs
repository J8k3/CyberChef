/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { generateEmvAesCmacCryptogram } from "../lib/EmvCryptogram.mjs";

/**
 * Generate EMV ARQC operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     NIST SP 800-38B — §6.2
 * @rule     AES-CMAC over the supplied preimage; the ARQC is the leftmost N bytes of the full CMAC.
 * @status   externally-verified
 * @evidence APC comparison 2026-05-19 (AES-CMAC MAC rows); ARQC-specific cross-check blocked by APC AES key-size constraint (issue #21)
 *
 * @spec     EMV 4.3 Book 2 — §8.1 (Application Cryptogram Generation)
 * @rule     Application cryptogram is a MAC over the CDOL1 data under the AC session key. The AES-CMAC profile implemented here covers AES kernels only; the TDES profile (ISO 9797-1 Algorithm 3) is not implemented by this operation.
 * @status   cited-unverified
 *
 * @spec     EMV 4.3 Book 2 — Annex A1.3 (Session Key Derivation) / A1.4 (Master Key Derivation)
 * @rule     Session-key and ICC-master-key derivation happen upstream and are intentionally out of scope: this operation takes the derived session key as an argument. For TDES flows note EMV pads the AC input per ISO 9797-1 Method 2 before MACing; APC's verify_auth_request_cryptogram expects the caller to pad (apc-hsm-proxy emv_pad, verified live).
 * @status   cited-unverified
 * @evidence apc-crossval arqc suite (2026-07-08 all-match) validates the Option A + EMV Common derivation chain from-spec against APC generate_auth_request_cryptogram, feeding CyberChef's Algorithm 3 MAC — corroborating the derivation model documented here
 */
class GenerateEMVARQC extends Operation {

    /**
     * GenerateEMVARQC constructor.
     */
    constructor() {
        super();

        this.name = "EMV Generate ARQC";
        this.module = "Payment";
        this.description = "Paste the already-assembled EMV authorization-request input into the input field as hex and generate an AES-CMAC-based ARQC.<br><br><b>Input:</b> preassembled ARQC input data as hex.<br><b>Arguments:</b> provide the EMV session key in hex and choose how many bytes of the CMAC should be returned.<br><br><b>Validation:</b> Partially verified. This intentionally covers only supplied-key AES-CMAC-style EMV profiles and does not derive EMV session keys or assemble CDOL data for you.<br><br><b>Session key derivation:</b> In a full EMV flow the ICC master key is first derived from the issuer master key and the PAN / PAN sequence number (EMV Book 2 Annex A1.4 — Option A for PANs up to 16 digits, Option B for longer PANs; selected by PAN length, not by scheme). The session key is then derived from the ICC master key in a scheme-specific step: EMV Common Session Key derivation (Annex A1.3) diversifies by ATC, Mastercard M/Chip SKD also incorporates the Unpredictable Number, and some Visa/Amex profiles use the ICC master key directly. This operation expects you to supply the already-derived session key — use a separate key-derivation step before calling this operation if you need to reproduce a full end-to-end flow.<br><br><b>Security:</b> Clear session keys are test-use only.";
        this.inlineHelp = "<strong>Input:</strong> preassembled ARQC data as hex.<br><strong>Args:</strong> provide the AES session key and choose the truncated cryptogram length.<br><strong>Validation:</strong> supplied-key AES-CMAC profile only.";
        this.testDataSamples = [
            {
                name: "AES-CMAC ARQC sample",
                input: "000102030405060708090A0B0C0D0E0F",
                args: ["00112233445566778899AABBCCDDEEFF", 8, false]
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/EMV";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Session key (hex)",
                type: "string",
                value: "",
                comment: "Provide the already-derived EMV session key as hex. Assumption: this op does not derive EMV session keys."
            },
            {
                name: "Cryptogram bytes",
                type: "number",
                value: 8,
                min: 1,
                max: 16,
                comment: "Number of leftmost CMAC bytes to return. Common ARQC length is <code>8</code> bytes."
            },
            {
                name: "Output as JSON",
                type: "boolean",
                value: false,
                comment: "When enabled, returns the full AES-CMAC and the truncated ARQC value."
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [sessionKeyHex, cryptogramBytes, outputJson] = args;
        const result = generateEmvAesCmacCryptogram(input, sessionKeyHex, cryptogramBytes);
        return outputJson ? JSON.stringify(result, null, 4) : result.cryptogramHex;
    }
}

export default GenerateEMVARQC;
