/**
 * @license Apache-2.0
 * @author Jacob Marks [https://jacobmarks.com]
 *
 * Grounding — one @spec group per load-bearing rule; see AGENTS.md "Spec grounding".
 *
 * @spec     Futurex Excrypt wire framing — Futurex HSM Reference Manual; corroborated by apc-hsm-proxy src/protocol/futurex.rs
 * @rule     Messages are bracket-delimited ("[" … "]"); the command field is "AO" + a 4-char code; parameters are a 2-char code + value, semicolon-delimited and NON-positional; responses carry a BB status field ("Y" = success, else an error code). Parameter semantics are command-scoped — the same 2-char code can mean different things in different commands, so tag meanings are only annotated per command, never globally.
 * @status   externally-verified
 * @evidence apc-hsm-proxy futurex.rs unit tests (parse_valid_tpin_frame, parse_params_splits_semicolon_delimited, frame_response_produces_bracket_delimited_output).
 *
 * @spec     Futurex Excrypt command catalogue
 * @rule     Command codes, names, and categories reconciled against the HSM command registry (44 Excrypt commands) plus the Futurex Payment Integration Guide command set already carried by this op.
 * @status   cited-unverified
 *
 * @spec     Per-command tags — TPIN (AW/AX/BT/AL/AK) and ECHO
 * @rule     TPIN field meanings from the apc-hsm-proxy TPIN handler; ECHO payload is echoed data with no parameter tags (Futurex HSM Reference Manual).
 * @status   cited-unverified
 * @evidence apc-hsm-proxy src/handlers/futurex/tpin.rs and echo.rs.
 *
 * @spec     Per-command tags — key exchange (GPGS/TWKA/TRTP: FS, BG, AE, AP, CT)
 * @rule     Key-exchange tag meanings from the AWS public Excrypt sample (key_exchange/hsm/futurex/commands.py). SINGLE SOURCE — not verified against the Futurex TRM/firmware; surfaced with a "medium confidence" note in the output.
 * @status   cited-unverified
 * @evidence Single-source public sample; a Futurex-experienced maintainer reviewed it as "generally correct" but could not confirm individual tag/enum semantics.
 */

import Operation from "../Operation.mjs";
import OperationError from "../errors/OperationError.mjs";

// Human-readable category labels. Category is descriptive metadata to help an
// analyst group commands; it is not a cryptographic claim.
const CATEGORY_LABELS = {
    PIN:  "PIN",
    MAC:  "MAC",
    CVV:  "Card Validation (CVV/CVC)",
    EMV:  "EMV / ARQC",
    KEY:  "Key Management",
    ENC:  "Encryption",
    P2PE: "P2PE / DUKPT",
};

// Excrypt command code -> [name, category]. Merged from the Futurex Payment
// Integration Guide set and the HSM command registry (which adds the health-
// check, key-generation, key-table, and TR-34 key-exchange commands).
const COMMANDS = {
    CAAV: ["Calculate Account Holder Authentication Value", "CVV"],
    DAPT: ["Decrypt Apple Pay Token", "ENC"],
    DCDK: ["Decrypt Cardholder Data Using DUKPT", "P2PE"],
    DGPT: ["Decrypt Google Pay Token", "ENC"],
    DRKI: ["Identification Request", "KEY"],
    DRKK: ["Key Request", "KEY"],
    DRKV: ["Key Verification Request", "KEY"],
    DSPT: ["Decrypt Samsung Pay Token", "ENC"],
    ECDK: ["Encrypt Cardholder Data Using DUKPT", "P2PE"],
    ECHO: ["HSM Echo / Health Check", "KEY"],
    EMPT: ["Translate PIN Block for EMV Personalization", "PIN"],
    EMVA: ["Verify ARQC and Optionally Generate ARPC", "EMV"],
    EMVG: ["Generate Master Key", "KEY"],
    EMVK: ["Derive Key from Vendor Master Key and Derivation Data", "KEY"],
    EMVM: ["Generate or Verify MAC (EMV)", "MAC"],
    EMVP: ["EMV PIN Change", "PIN"],
    EMVR: ["Translate EMV RSA Private Key to a Personalization Key", "KEY"],
    EMVS: ["Translate an ICC Master Key to a Personalization Key", "KEY"],
    EMVT: ["EMV Translate Sensitive Data", "ENC"],
    GCAV: ["Generate CAVV", "CVV"],
    GCIV: ["Generate a CVC3 IV", "CVV"],
    GCSC: ["Generate American Express CSC Value", "CVV"],
    GCVC: ["Generate CVC and CVC2", "CVV"],
    GCVV: ["Generate CVV or CVC Value", "CVV"],
    GDAC: ["Generate a Data Authentication Code", "MAC"],
    GDCV: ["Generate dCVV/CVC3", "CVV"],
    GDDC: ["Generate Discover Dynamic CVV", "CVV"],
    GECC: ["Generate ECC Key Pair", "KEY"],
    GEMC: ["Generate EMV ICC Certificate", "KEY"],
    GEMQ: ["Generate EMV Issuer CSR", "KEY"],
    GCKD: ["Derive Key from Shared Secret", "KEY"],
    GHMC: ["Generate HCE Mobile Cryptogram", "EMV"],
    GHMD: ["Generate HCE Magstripe Verification Value", "CVV"],
    GHMK: ["Generate HCE Mobile Keys", "KEY"],
    GHPB: ["Generate HMAC and PBKDF2 Obfuscated Value", "MAC"],
    GIDN: ["Generate an ICC Dynamic Number", "EMV"],
    GKBL: ["Translate Cryptogram to TR-31 Key Block", "KEY"],
    GMAC: ["Generate Message Authentication Code", "MAC"],
    GNOF: ["Generate New Offset", "PIN"],
    GOFC: ["Generate Offset of Clear PIN", "PIN"],
    GOFF: ["Generate PIN Offset Value", "PIN"],
    GOPC: ["Generate Offset and EMV PIN Change", "PIN"],
    GPGS: ["General Purpose Generate Symmetric Key", "KEY"],
    GPIN: ["Generate PIN", "PIN"],
    GPKR: ["General Purpose Key Settings Get", "KEY"],
    GPMC: ["General Purpose Symmetric MAC", "MAC"],
    GPRW: ["Get Public RSA Wrapping Key", "KEY"],
    GRSA: ["Generate RSA Key Pair", "KEY"],
    GVDC: ["Generate Dynamic CVV", "CVV"],
    HMAC: ["Generate MAC Hash", "MAC"],
    KMAP: ["Bitmap Key Table", "KEY"],
    OFPC: ["Perform EMV PIN Change Using Offset", "PIN"],
    ONGQ: ["Translate PAN to a Different Trusted Public Key", "ENC"],
    PEDK: ["Key Request (TR-34 Remote Key Loading)", "KEY"],
    RKHM: ["Generate or Verify HMAC", "MAC"],
    RPIN: ["PIN Change and Optional PIN Verification", "PIN"],
    RSAR: ["Import Key Under RSA", "KEY"],
    AVPC: ["Add / Trust Public Certificate", "KEY"],
    RVPC: ["Receive / Verify Public Certificate", "KEY"],
    SDDH: ["ECDH Shared-Secret Derivation", "KEY"],
    SSAD: ["Sign Static Authentication Data with Issuer Private Key", "KEY"],
    TCDK: ["Translate Cardholder Data Using DUKPT", "P2PE"],
    TDKD: ["Translate Cardholder Data Using DUKPT and Symmetric Keys", "P2PE"],
    TKDR: ["Translate DUKPT Data to RSA with Specific Output Data", "P2PE"],
    TPCP: ["Translate Encrypted PIN Coordinates to a PEK", "PIN"],
    TPDD: ["Translate an Encrypted ANSI PIN Block", "PIN"],
    TPIN: ["Translate PIN Block", "PIN"],
    TROP: ["TR-34 Key Export (Translate Out)", "KEY"],
    TRPN: ["Translate PIN from RSA to Symmetric PIN Block", "PIN"],
    TRTD: ["TR-34 Key Import (Translate In)", "KEY"],
    TRTP: ["TR-34 Payload Produce / Translate", "KEY"],
    TSPN: ["Translate PIN from PIN Block to RSA Encryption", "PIN"],
    TWKA: ["Translate Working Key (Asymmetric KEK)", "KEY"],
    TWKS: ["Translate Working Key (Symmetric KEK Import)", "KEY"],
    VAAV: ["Verify Account Holder Authentication Value", "CVV"],
    VCAC: ["Verify EMV Mastercard CAP Token", "EMV"],
    VCAV: ["Verify Cardholder Authentication Verification Value", "CVV"],
    VCSC: ["Verify American Express CSC Value", "CVV"],
    VCVC: ["Verify CVC and CVC2", "CVV"],
    VCVV: ["Verify CVV", "CVV"],
    VDAC: ["Verify a Data Authentication Code", "MAC"],
    VDCV: ["Verify CVC3", "CVV"],
    VDDC: ["Verify Dynamic CVC Value", "CVV"],
    VEMI: ["Verify an EMV Issuer Certificate", "KEY"],
    VHMC: ["Verify HCE Mobile Cryptogram", "EMV"],
    VHMD: ["Verify HCE Magstripe Verification Value", "CVV"],
    VIDN: ["Verify an ICC Dynamic Number", "EMV"],
    VKTE: ["Verify Key Table Entry", "KEY"],
    VMAC: ["Verify Message Authentication Code", "MAC"],
    VMAP: ["Verify MAC and PIN", "PIN"],
    VPIN: ["Verify PIN", "PIN"],
    VVDC: ["Verify a Dynamic CVV", "CVV"],
    WPIN: ["Weak PIN Checking", "PIN"],
    XPIN: ["Extended PIN Translation", "PIN"],
};

// Per-command parameter tag maps. Only commands whose field semantics are
// documented appear here; because Excrypt parameter meanings are command-scoped,
// tags are never interpreted for a command that is not in this table.
//   confidence "high"   — from the Futurex HSM Reference Manual or a tested handler
//   confidence "medium" — single public source, not TRM/firmware-verified
const COMMAND_TAGS = {
    TPIN: {
        confidence: "high",
        tags: {
            AW: "Mode / options flag (command-scoped)",
            AX: "Incoming (source) key",
            BT: "Outgoing (destination) key",
            AL: "PIN block",
            AK: "Account number (PAN)",
        },
    },
    ECHO: {
        confidence: "high",
        rawPayload: true,
        note: "Connectivity / health check — the payload is arbitrary data echoed back, not tagged parameters.",
        tags: {},
    },
    GPGS: {
        confidence: "medium",
        note: "Key-exchange tag meanings are from a single public source and are not verified against the Futurex module documentation.",
        tags: {
            FS: "Major / master-key selector (FS6 = PMK / AES)",
            BG: "Wrapped key block (output)",
            AE: "Key check value (KCV)",
            CT: "Symmetric algorithm (2=TDES2, 3=TDES3, 4=AES128, 5=AES192, 6=AES256)",
        },
    },
    TWKA: {
        confidence: "medium",
        note: "Key-exchange tag meanings are from a single public source and are not verified against the Futurex module documentation.",
        tags: {
            FS: "Major / master-key selector",
            BG: "Wrapped key block",
            AE: "Key check value (KCV)",
            AP: "Key-encryption key (KEK)",
            CT: "Symmetric algorithm (2=TDES2, 3=TDES3, 4=AES128, 5=AES192, 6=AES256)",
        },
    },
    TRTP: {
        confidence: "medium",
        note: "Builds a TR-34 export payload. Tag meanings are from a single public source and are not verified against the Futurex module documentation.",
        tags: {
            FS: "Major / master-key selector",
            BG: "Wrapped key block",
            AP: "Key-encryption key (KEK)",
        },
    },
};

/**
 * Splits an Excrypt field into a 2-char tag and its value.
 *
 * @param {string} field
 * @returns {{raw: string, tag: string, value: string}}
 */
function parseField(field) {
    const tag = field.substring(0, Math.min(2, field.length)).toUpperCase();
    return {
        raw: field,
        tag,
        value: field.substring(tag.length),
    };
}

/**
 * Parse Futurex Excrypt Command operation.
 */
class ParseFuturexExcryptCommand extends Operation {

    /**
     * ParseFuturexExcryptCommand constructor
     */
    constructor() {
        super();

        this.name = "HSM Parse Futurex Command";
        this.module = "Payment";
        this.description = "Paste a Futurex Excrypt command or response into the input field as text.<br><br><b>Scope:</b> This operation performs syntax parsing and labelling only. It splits the bracketed message into tag/value fields, resolves the command code to a name and category, and — for commands whose fields are documented — labels each parameter with its per-command meaning. It does not interpret, validate, or execute the command; field values and key material are not checked.<br><br><b>Syntax:</b> Excrypt messages are enclosed in <code>[</code> and <code>]</code>. Fields are semicolon-delimited. The command field is <code>AO</code> + a 4-character code, e.g. <code>AOECHO</code>. Every other field is a 2-character tag followed by its value; fields are <b>not positional</b>. Responses carry a <code>BB</code> status field (<code>Y</code> = success, otherwise an error code).<br><br><b>Command-scoped tags:</b> the same 2-character tag can mean different things in different commands, so parameter meanings are shown only for commands with a documented tag map, and are never assumed across commands.<br><br><b>Input:</b> raw Excrypt message text.";
        this.inlineHelp = "<strong>Scope:</strong> syntax parser and labeller — fields are split, the command is named/categorised, and documented tags are labelled; nothing is validated or executed.<br><strong>Syntax:</strong> <code>[AO&lt;cmd&gt;;&lt;tag&gt;&lt;value&gt;;...]</code>; the <code>BB</code> field carries the response status.<br><strong>Input:</strong> raw Futurex Excrypt message text.";
        this.testDataSamples = [
            {
                name: "Excrypt TPIN command (documented tags)",
                input: "[AOTPIN;AW1;AK561237487695;AL1234567890ABCDEF;]"
            },
            {
                name: "Excrypt ECHO health check",
                input: "[AOECHO;ping;]"
            }
        ];
        this.infoURL = "https://en.wikipedia.org/wiki/Hardware_security_module";
        this.inputType = "string";
        this.outputType = "string";
        this.args = [];
    }

    /**
     * @param {string} input
     * @returns {string}
     */
    run(input) {
        const rawInput = (input || "").replace(/\r?\n/g, "");
        if (!rawInput.length) {
            throw new OperationError("No input.");
        }

        const openingDelimiterPresent = rawInput.startsWith("[");
        const closingDelimiterPresent = rawInput.endsWith("]");
        const body = rawInput.replace(/^\[/, "").replace(/\]$/, "");
        const rawFields = body.split(";").filter(field => field.length > 0);

        if (!rawFields.length) {
            throw new OperationError("No Excrypt fields found.");
        }

        const parsedFields = rawFields.map(parseField);
        const commandField = parsedFields.find(field => field.tag === "AO") || parsedFields[0];
        const commandCode = commandField.value.toUpperCase();
        const entry = COMMANDS[commandCode] || null;
        const commandName = entry ? entry[0] : null;
        const commandCategory = entry ? CATEGORY_LABELS[entry[1]] : null;
        const tagMap = Object.prototype.hasOwnProperty.call(COMMAND_TAGS, commandCode) ? COMMAND_TAGS[commandCode] : null;

        const notes = [];
        const unexpectedTags = [];
        let status = null;

        // Annotate each field. Tag meanings are only applied per command; the
        // AO command field and the BB status field are framing-level and common.
        const fields = parsedFields.map(field => {
            const out = { raw: field.raw, tag: field.tag, value: field.value };

            if (field === commandField && field.tag === "AO") {
                out.meaning = "Command code";
                return out;
            }
            if (field.tag === "BB") {
                out.meaning = "Response status";
                status = field.value.toUpperCase() === "Y" ?
                    "success" :
                    `error (code ${field.value})`;
                out.statusDescription = status;
                return out;
            }
            if (tagMap && tagMap.rawPayload) {
                out.meaning = "Free-form payload (not a tagged parameter)";
            } else if (tagMap) {
                if (Object.prototype.hasOwnProperty.call(tagMap.tags, field.tag)) {
                    out.meaning = tagMap.tags[field.tag];
                    out.permitted = true;
                } else {
                    out.permitted = false;
                    unexpectedTags.push(field.tag);
                }
            }
            return out;
        });

        if (!openingDelimiterPresent || !closingDelimiterPresent) {
            notes.push("Message is missing one or both expected Excrypt outer delimiters.");
        }
        if (!commandName) {
            notes.push("Command code was not recognised. Field tags are shown but not interpreted.");
        }
        if (tagMap && tagMap.confidence === "medium") {
            notes.push("Parameter tag meanings for this command come from a single public source and are not verified against the Futurex module documentation — treat as a guide.");
        }
        if (tagMap && tagMap.note) {
            notes.push(tagMap.note);
        }
        if (unexpectedTags.length) {
            notes.push(`Tag(s) not documented for ${commandCode}: ${[...new Set(unexpectedTags)].join(", ")}. Parameter meanings are command-scoped, so these are left unlabelled.`);
        }

        const result = {
            rawInput,
            openingDelimiterPresent,
            closingDelimiterPresent,
            body,
            rawFields,
            fields,
            commandFieldTag: commandField.tag,
            commandCode,
            commandName,
            commandCategory,
            fieldCount: fields.length,
        };
        if (status !== null) {
            result.responseStatus = status;
        }
        result.notes = notes;

        return JSON.stringify(result, null, 4);
    }
}

export default ParseFuturexExcryptCommand;
