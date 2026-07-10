/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { generateVisaPvv } from "../lib/PaymentPinVerification.mjs";

/**
 * Generate VISA PVV operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     Visa PVV / ABA PVV method — Thales payShield PUGD0537-004 Rev A p.273 (DC), p.259 (CU); APC VisaPinVerificationValue
 * @rule     TSP = rightmost 11 PAN digits excluding the check digit || PVKI || leftmost 4 PIN digits; TDES-encrypt under the PVK; decimalize two-pass (digits first, then A–F mapped to 0–5). The payShield manual calls this the "ABA PVV" method — the algorithm Visa adopted as its PVV.
 * @status   externally-verified
 * @evidence apc-crossval 2impl differential vs APC generate_pin_data VisaPinVerificationValue (randomized PAN/PVKI/PIN, shared clear PVK, PIN carried as ISO-0 block under a shared PEK), 2026-07-08 all-match; also APC verify_pin_data cross-checks 2026-05-19.
 */
class GenerateVISAPVV extends Operation {
    /**
     * GenerateVISAPVV constructor.
     */
    constructor() {
        super();

        this.name = "VISA PVV Generate";
        this.module = "Payment";
        this.description = "Paste the clear PIN into the input field and generate a VISA PIN Verification Value (PVV).<br><br><b>Input:</b> clear PIN digits.<br><b>Arguments:</b> provide the clear PVK in hex, PAN, and PVKI.<br><br><b>Validation:</b> Partially verified. This is a clear-key software implementation of the common VISA PVV assembly pattern, not an HSM-certified PVV service.<br><br><b>Security:</b> Clear PIN and PVK material are test-use only.";
        this.inlineHelp = "<strong>Input:</strong> clear PIN digits.<br><strong>Args:</strong> provide PVK, PAN, and PVKI.<br><strong>Validation:</strong> clear-key VISA PVV helper.";
        this.testDataSamples = [
            {
                name: "VISA PVV sample",
                input: "__RANDOM_PIN_4__",
                args: ["0123456789ABCDEFFEDCBA9876543210", "5432101234567890", 1, true]
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/ISO_9564";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            { name: "PIN verification key (hex)", type: "string", value: "", comment: "Provide the clear VISA PVK as 16-byte or 24-byte hex." },
            { name: "Primary account number", type: "string", value: "", comment: "Provide the PAN as digits only. The standard PVV input uses the rightmost 11 digits before the check digit." },
            { name: "PVKI", type: "number", value: 1, min: 0, max: 6, comment: "PIN verification key index from 0 through 6." },
            { name: "Output as JSON", type: "boolean", value: true, comment: "When enabled, returns the assembled PVV input and intermediate encrypted block." },
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [pvkHex, pan, pvki, outputJson] = args;
        const result = generateVisaPvv(pvkHex, pan, pvki, input);
        return outputJson ? JSON.stringify(result, null, 4) : result.pvv;
    }
}

export default GenerateVISAPVV;
