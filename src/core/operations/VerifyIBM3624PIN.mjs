/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { verifyIbm3624Pin } from "../lib/PaymentPinVerification.mjs";

/**
 * Verify IBM 3624 PIN operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     IBM 3624 PIN offset method — as specified in Thales payShield PUGD0537-004 and APC Ibm3624PinVerification
 * @rule     Re-derives the offset from the supplied PIN and compares significant digits only (one per PIN digit).
 * @status   externally-verified
 * @evidence APC verify_pin_data cross-check 2026-05-19 (PASS)
 *
 * @spec     Thales payShield wire convention — PUGD0537-004 Rev A p.263 (DA) / p.255 (DU) / p.349 (GO); PUGD0538-003 p.112 (CK)
 * @rule     The 12-character F-padded offset field is accepted directly: trailing 'F' fill is stripped before comparison because the offset is defined only for its significant digits (one per PIN digit).
 * @status   vendor-convention
 * @evidence apc-hsm-proxy issue #21 — passing the raw padded field to a significant-digits comparator rejects every valid PIN; confirmed live in three proxy handlers
 */
class VerifyIBM3624PIN extends Operation {
    /**
     * VerifyIBM3624PIN constructor.
     */
    constructor() {
        super();

        this.name = "PIN IBM 3624 Verify";
        this.module = "Payment";
        this.description = "Paste the stored PIN offset into the input field and verify it against a clear PIN.<br><br><b>Input:</b> stored IBM 3624 PIN offset (4 to 12 decimal digits). Trailing <code>F</code> fill is ignored, so the fixed 12-character F-padded offset field used by HSM wire formats (e.g. Thales payShield DA/DU/CK) can be pasted directly.<br><b>Arguments:</b> provide the clear PVK in hex, decimalization table, validation data, pad character, and the clear PIN to verify.<br><br>This operation re-derives the offset from the supplied PIN and keying material and compares it to the input offset. Use this directly after <b>PIN IBM 3624 Offset Generate</b> in a recipe — the offset output flows naturally into this input.<br><br><b>Validation:</b> Partially verified. This is the verification pair for the same clear-key IBM 3624 helper logic used by generation.<br><br><b>Security:</b> Clear PIN and PVK material are test-use only.";
        this.inlineHelp = "<strong>Input:</strong> stored IBM 3624 PIN offset.<br><strong>Args:</strong> provide PVK, decimalization table, validation data, pad character, and the clear PIN to verify.<br><strong>Validation:</strong> clear-key IBM 3624 verification helper.";
        this.testDataSamples = [
            {
                name: "IBM 3624 verify sample",
                input: "3207",
                args: ["0123456789ABCDEFFEDCBA9876543210", "0123456789012345", "5432101234567890", "F", "1234", true]
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/IBM_3624";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            { name: "PIN verification key (hex)", type: "string", value: "", comment: "Provide the clear IBM 3624 PVK as 16-byte or 24-byte hex." },
            { name: "Decimalization table", type: "string", value: "0123456789012345", comment: "Sixteen decimal digits used to map hex nibbles to decimal digits." },
            { name: "PIN validation data", type: "string", value: "", comment: "Issuer validation data, typically PAN-derived digits, 4 to 16 digits." },
            { name: "Pad character", type: "shortString", value: "F", comment: "Single hex nibble used to right-pad validation data to 16 nibbles." },
            { name: "Clear PIN", type: "string", value: "", comment: "The PIN to verify. The operation re-derives the offset from this PIN and compares it to the input offset." },
            { name: "Output as JSON", type: "boolean", value: true, comment: "When enabled, returns the recomputed offset and validity result." },
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [pvkHex, decimalizationTable, pinValidationData, padCharacter, pin, outputJson] = args;
        const result = verifyIbm3624Pin(pvkHex, decimalizationTable, pinValidationData, padCharacter, input, pin);
        return outputJson ? JSON.stringify(result, null, 4) : String(result.valid);
    }
}

export default VerifyIBM3624PIN;
