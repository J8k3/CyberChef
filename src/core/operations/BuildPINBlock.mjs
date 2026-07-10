/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 */

import Operation from "../Operation.mjs";
import { PIN_BLOCK_FORMATS, buildPinBlock } from "../lib/PinBlock.mjs";

/**
 * Build PIN block operation
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     ISO 9564-1:2017 — §9.3.2 (Format 0), §9.3.3 (Format 1), §9.3.5 (Format 3)
 * @rule     Format 0: PIN field filled with 0xF, XORed with the PAN field. Format 1: fill is random (or a transaction number). Format 3: fill digits drawn from 0xA–0xF, XORed with the PAN field.
 * @status   externally-verified
 * @evidence APC PIN Block Translate Encrypted cross-check 2026-05-19 exercises Format 0 end-to-end
 *
 * @spec     ISO 9564-1:2017 — §9.3.2
 * @rule     PAN field = the 12 rightmost PAN digits excluding the check digit, left-padded with zeros. Note this is NOT the EMV Option A convention (rightmost 16 of PAN||PSN, EMV Book 2 Annex A1.4.1) — conflating the two corrupted PAN decoding in apc-hsm-proxy (issue #19).
 * @status   externally-verified
 * @evidence Format 0 deterministic vector cross-checked via APC 2026-05-19
 */
class BuildPINBlock extends Operation {

    /**
     * BuildPINBlock constructor
     */
    constructor() {
        super();

        this.name = "PIN Block Build";
        this.module = "Payment";
        this.description = "Paste the clear PIN into the input field and choose the ISO 9564 clear PIN block format to build.<br><br><b>Input:</b> clear PIN digits.<br><b>Arguments:</b> choose the target format, provide the PAN when required, and optionally randomize filler digits for formats 1 and 3.<br><br>This operation currently builds clear test PIN blocks for ISO formats 0, 1, and 3.";
        this.inlineHelp = "<strong>Input:</strong> clear PIN digits.<br><strong>Args:</strong> choose the format, add the PAN for formats 0 and 3, then decide whether format 1 or 3 filler digits should be randomized.";
        this.testDataSamples = [
            {
                name: "Random ISO Format 0 sample",
                input: "__RANDOM_PIN_4__",
                args: ["ISO Format 0", "__RANDOM_PAN_16__", false]
            }
        ];
        this.infoURL = "https://wikipedia.org/wiki/ISO_9564";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [
            {
                name: "Format",
                type: "option",
                value: PIN_BLOCK_FORMATS,
                comment: "Choose the clear ISO 9564 block format to build. Assumption: only formats <code>0</code>, <code>1</code>, and <code>3</code> are implemented."
            },
            {
                name: "Primary account number",
                type: "string",
                value: "",
                comment: "Required for formats 0 and 3. Enter digits only; the implementation uses the rightmost 12 digits excluding the check digit."
            },
            {
                name: "Randomize fill digits",
                type: "boolean",
                value: false,
                comment: "Affects only formats 1 and 3. When disabled, filler is deterministic so test vectors stay stable."
            }
        ];
    }

    /**
     * @param {string} input
     * @param {Object[]} args
     * @returns {string}
     */
    run(input, args) {
        const [format, pan, randomizeFill] = args;
        return buildPinBlock(format, input, pan, randomizeFill);
    }
}

export default BuildPINBlock;
