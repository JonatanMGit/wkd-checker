#!/usr/bin/env node
import { checkKey, KeyCheckResult } from './index';

// ANSI Colors and Styles
const RESET = "\x1b[0m";
const BOLD = "\x1b[1m";
const DIM = "\x1b[2m";

const RED = "\x1b[31m";
const GREEN = "\x1b[32m";
const CYAN = "\x1b[36m";

// Symbols
const CHECK_MARK = "\u2713"; // ✓
const CROSS_MARK = "\u2717"; // ✗

const formatStatus = (isValid: boolean, label: string) => {
    if (isValid) {
        return `${GREEN}${CHECK_MARK} ${label}${RESET}`;
    }
    return `${RED}${CROSS_MARK} Invalid${RESET}`;
};

const formatBoolean = (val: boolean) => val ? formatStatus(true, "Valid") : formatStatus(false, "Invalid");

const printSection = (title: string, result: KeyCheckResult) => {
    const isWorking = result.valid;
    const titleColor = isWorking ? GREEN : RED;
    const statusLabel = isWorking ? "Working" : "Not Working";
    const statusBadge = isWorking ? `${GREEN} ${statusLabel} ${RESET}` : `${RED} ${statusLabel} ${RESET}`;

    console.log(`\n${BOLD}${title}${RESET} ${statusBadge}`);
    console.log(`${DIM}------------------------------------------------------------${RESET}`);

    console.log(`Policy Available:   ${formatBoolean(result.policyAvailable)}`);
    console.log(`Policy CORS Valid:  ${formatBoolean(result.policyCorsValid)}`);

    console.log(`\nKey Location:       ${CYAN}${result.key_location || 'N/A'}${RESET}`);

    console.log(`\nKey Available:      ${formatBoolean(result.key_available)}`);
    console.log(`Key CORS Valid:     ${formatBoolean(result.keyCorsValid)}`);

    console.log(`Key Type:           ${result.keyTypeValid ? GREEN : RED}${result.keyType}${RESET}`);

    console.log(`Fingerprint:        ${BOLD}${result.fingerprint || 'N/A'}${RESET}`);

    console.log(`Email in Key:       ${formatBoolean(result.emailInKey)}`);
};

async function main() {
    const args = process.argv.slice(2);
    const jsonOutput = args.includes('--json');
    const cleanArgs = args.filter((arg: string) => arg !== '--json');

    if (cleanArgs.length !== 1) {
        console.error(`${RED}Error: Please provide exactly one email address.${RESET}`);
        console.log(`Usage: wkd-checker <email> [--json]`);
        process.exit(1);
    }

    const email = cleanArgs[0];

    if (!jsonOutput) {
        console.log(`Checking WKD status for: ${BOLD}${email}${RESET}...`);
    }

    try {
        const results = await checkKey(email);
        const isOverallValid = results.direct.valid || results.advanced.valid;

        if (jsonOutput) {
            console.log(JSON.stringify(results, null, 2));
            process.exit(isOverallValid ? 0 : 1);
        }

        printSection("Direct Method", results.direct);

        printSection("Advanced Method", results.advanced);

        console.log(`\n${BOLD}Overall Status${RESET}`);
        console.log(`${DIM}------------------------------------------------------------${RESET}`);
        console.log(`Valid: ${formatBoolean(isOverallValid)}`);

        process.exit(isOverallValid ? 0 : 1);

    } catch (error: any) {
        if (jsonOutput) {
            console.error(JSON.stringify({ error: error.message || error }));
            process.exit(1);
        }
        console.error(`\n${RED}${CROSS_MARK} Error:${RESET} ${error.message || error}`);
        process.exit(1);
    }
}

main();
