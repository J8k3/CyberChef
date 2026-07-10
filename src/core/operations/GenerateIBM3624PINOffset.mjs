/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { generateIbm3624PinOffset } from "../lib/PaymentPinVerification.mjs";

/**
 * Generate IBM 3624 PIN offset operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     IBM 3624 PIN offset method — as specified in Thales payShield PUGD0537-004 Rev A p.263 (DA) / p.255 (DU) / p.349 (GO) and APC Ibm3624PinOffset
 * @rule     Offset digit i = (PIN digit i − natural PIN digit i) mod 10, where the natural PIN is the decimalized TDES encryption of the validation data padded to 16 with the pad character ('F' by convention). The offset has exactly one significant digit per PIN digit; natural PIN = all-zero offset.
 * @status   externally-verified
 * @evidence apc-crossval 2impl differential vs APC generate_pin_data Ibm3624PinOffset (randomized PAN/PIN/decimalization table, shared clear PVK), latest run 2026-07-08 all-match; APC verify_pin_data cross-check 2026-05-19 (offset 0324 MATCH)
 *
 * @spec     Thales payShield wire convention — PUGD0537-004 Rev A p.263 (DA) / p.255 (DU) / p.349 (GO); PUGD0538-003 p.112 (CK)
 * @rule     HSM wire formats carry the offset as a fixed 12-character field left-justified and right-padded with 'F'; this operation emits only the significant digits (APC convention: ^[0-9]+$). Append 'F' fill yourself if a consumer requires the fixed-width field.
 * @status   vendor-convention
 * @evidence apc-hsm-proxy issue #21 — live differentials caught the raw-padded-offset bug in three handlers (GO returned error 41 for every valid PIN); proxy strips before the APC call and re-pads the DV response field
 */
class GenerateIBM3624PINOffset extends Operation {
    /**
     * GenerateIBM3624PINOffset constructor.
     */
    constructor() {
        super();

        this.name = "PIN IBM 3624 Offset Generate";
        this.module = "Payment";
        this.description = "Paste the clear PIN into the input field and generate the IBM 3624 offset used by issuer-side PIN verification.<br><br><b>Input:</b> clear PIN digits.<br><b>Arguments:</b> provide the clear PVK in hex, decimalization table, validation data, and pad character.<br><br><b>Validation:</b> Partially verified. This is a clear-key software implementation of the IBM 3624 PIN offset scheme rather than HSM-certified behavior.<br><br><b>Security:</b> Clear PIN and PVK material are test-use only.";
        this.inlineHelp = "<strong>Input:</strong> clear PIN digits.<br><strong>Args:</strong> provide PVK, decimalization table, validation data, and pad character.<br><strong>Validation:</strong> clear-key IBM 3624 helper.";
        this.testDataSamples = [
            {
                name: "IBM 3624 offset sample",
                input: "__RANDOM_PIN_4__",
                args: ["0123456789ABCDEFFEDCBA9876543210", "0123456789012345", "5432101234567890", "F", true]
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
            { name: "Output as JSON", type: "boolean", value: true, comment: "When enabled, returns the intermediate natural PIN and validation-block details." },
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [pvkHex, decimalizationTable, pinValidationData, padCharacter, outputJson] = args;
        const result = generateIbm3624PinOffset(pvkHex, decimalizationTable, pinValidationData, padCharacter, input);
        return outputJson ? JSON.stringify(result, null, 4) : result.pinOffset;
    }
}

export default GenerateIBM3624PINOffset;
