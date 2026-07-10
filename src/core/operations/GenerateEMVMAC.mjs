/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { generateEmvMac } from "../lib/EmvMac.mjs";

/**
 * Generate EMV MAC operation.
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     EMV 4.3 Book 2 — §9.2.3 (MAC Computation) / Annex A1.2; payShield PUGD0537-004 Rev A p.475 (KU)
 * @rule     Secure-messaging MAC for issuer scripts: ISO 9797-1 Algorithm 3 (retail MAC) under the session integrity key (SK-SMI), message padded per ISO 9797-1 Method 2 (0x80 then zeros). Issuer-script MACs are conventionally 4 bytes. Note APC's EmvMac does NOT pad MessageData — the caller pads before the call (apc-hsm-proxy, verified live).
 * @status   cited-unverified
 * @evidence Section numbering verified against EMV Book 2 TOC (2026-07-08); padding/length behavior from apc-hsm-proxy issuer_script_mac live differentials (15/15). APC comparison 2026-05-19 mismatched under default Method 2 — APC generate_mac EmvMac derives SK-SMI internally from the IMK (MCP KB issue #16), so a direct-key comparison is not like-for-like; a supplied-SK 2impl check of this op remains open
 *
 * @spec     ISO 9797-1:2011 — §7.4
 * @rule     Underlying retail-MAC construction shared with MAC Generate.
 * @status   externally-verified
 * @evidence APC comparison 2026-05-19 (ISO9797_ALGORITHM3 MATCH)
 */
class GenerateEMVMAC extends Operation {
    /**
     * GenerateEMVMAC constructor.
     */
    constructor() {
        super();

        this.name = "EMV Generate MAC";
        this.module = "Payment";
        this.description = "Paste the issuer-script or EMV command payload into the input field as hex and generate an EMV MAC.<br><br><b>Input:</b> message data as hex.<br><b>Arguments:</b> provide the already-derived EMV session integrity key and choose how many leftmost MAC bytes to return.<br><br><b>Validation:</b> Partially verified. This implements a retail-MAC style EMV helper with a supplied session key, not full EMV session derivation or brand-specific issuer processing.<br><br><b>Key context:</b> In a full issuer implementation, the session integrity key used here corresponds to the secure-messaging integrity key (distinct from the confidentiality key used to encrypt data and the PIN encryption key used for PIN blocks). This operation accepts any key you supply and does not enforce that separation.<br><br><b>Security:</b> Clear session keys in the recipe are test-use only.";
        this.inlineHelp = "<strong>Input:</strong> issuer-script message data as hex.<br><strong>Args:</strong> provide the derived EMV session integrity key.<br><strong>Validation:</strong> supplied-key EMV MAC helper, not full EMV derivation.";
        this.testDataSamples = [
            {
                name: "EMV MAC sample",
                input: "8424000008999E57FD0F47CACE0007",
                args: ["0123456789ABCDEFFEDCBA9876543210", "Method 2", 8, false]
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/EMV";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            { name: "Session integrity key (hex)", type: "string", value: "", comment: "Provide the already-derived EMV integrity session key in hex. This op does not derive EMV keys for you." },
            { name: "Padding method", type: "option", value: ["Method 2", "Method 1"], comment: "Method 2 appends 0x80 then zero-pads to block boundary (ISO 7816-4; standard for EMV issuer scripts). Method 1 zero-pads to block boundary only." },
            { name: "Output bytes", type: "number", value: 8, min: 1, max: 8, comment: "Number of leftmost MAC bytes to return. EMV issuer scripts commonly use 8 bytes." },
            { name: "Output as JSON", type: "boolean", value: false, comment: "When enabled, returns the issuer-script input and full retail-MAC details." },
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [sessionKeyHex, paddingMethod, outputBytes, outputJson] = args;
        const result = generateEmvMac(input, sessionKeyHex, outputBytes, paddingMethod);
        return outputJson ? JSON.stringify(result, null, 4) : result.macHex;
    }
}

export default GenerateEMVMAC;
