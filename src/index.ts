import { Key, readKey } from 'openpgp';

/**
 * Result of a key check operation.
 */
export interface KeyCheckResult {
    policyAvailable: boolean;
    policyCorsValid: boolean;
    key_location: string | null;
    key_available: boolean;
    keyCorsValid: boolean;
    keyType: KeyType;
    fingerprint: string | null;
    emailInKey: boolean;
    valid: boolean;
}

/**
 * Enum representing the type of key found.
 */
export enum KeyType {
    Invalid = 'Invalid',
    BinaryKey = 'BinaryKey',
    ArmoredKey = 'ArmoredKey',
}

export class WKDError extends Error {
    constructor(message: string) {
        super(message);
        this.name = "WKDError";
    }
}


const EMAIL_REGEX = /^[^@]+@[^@]+\.[^@]+$/;

/**
 * Validates an email address format.
 * @param {string} email - The email address to validate.
 * @returns {boolean} True if the email is valid, false otherwise.
 */
export const validateEmail = (email: string): boolean => EMAIL_REGEX.test(email);

/**
 * Fetches a URL and checks for CORS headers.
 * @param {string} url - The URL to fetch.
 * @param {RequestInit} options - Fetch options.
 * @returns {Promise<{ response: Response | null, corsValid: boolean }>} The response and CORS validity status.
 */
const fetchWithCorsCheck = async (url: string, options: RequestInit): Promise<{ response: Response | null, corsValid: boolean }> => {
    try {
        const response = await fetch(url, options);
        const corsValid = response.headers.get("access-control-allow-origin") === "*";
        return { response: response.ok ? response : null, corsValid };
    } catch {
        return { response: null, corsValid: false };
    }
}

/**
 * Detects the type of OpenPGP key (Armor or Binary).
 * @param {Response} keyData - The response containing the key data.
 * @returns {Promise<{ keyType: KeyType, key: Key | null }>} The detected key type and parsed key object.
 */
const detectKeyType = async (keyData: Response): Promise<{ keyType: KeyType, key: Key | null }> => {
    try {
        const buffer = await keyData.clone().arrayBuffer();
        const binaryKey = new Uint8Array(buffer);

        const header = "-----BEGIN PGP PUBLIC KEY BLOCK-----";
        const prefix = new TextDecoder().decode(binaryKey.slice(0, header.length));

        if (prefix === header) {
            const text = new TextDecoder().decode(binaryKey);
            const key = await readKey({ armoredKey: text });
            return { keyType: KeyType.ArmoredKey, key };
        } else {
            const key = await readKey({ binaryKey });
            return { keyType: KeyType.BinaryKey, key };
        }
    } catch {
        return { keyType: KeyType.Invalid, key: null };
    }
}

/**
 * Checks for a key at a specific WKD URL.
 * @param {string} url - The WKD URL for the key.
 * @param {string} policy - The policy URL.
 * @param {RequestInit} options - Fetch options.
 * @param {string} email - The email address used to verify the key user ID.
 * @returns {Promise<KeyCheckResult>} The result of the key check.
 */
const checkKeyUrl = async (url: string, policy: string, options: RequestInit, email: string): Promise<KeyCheckResult> => {
    const [policyData, keyData] = await Promise.all([
        fetchWithCorsCheck(policy, options),
        fetchWithCorsCheck(url, options)
    ]);

    const result: KeyCheckResult = {
        policyAvailable: !!policyData.response,
        policyCorsValid: policyData.corsValid,
        key_location: keyData.response?.url || url,
        key_available: !!keyData.response,
        keyCorsValid: keyData.corsValid,
        keyType: KeyType.Invalid,
        fingerprint: null,
        emailInKey: false,
        valid: false,
    };

    if (keyData.response) {
        const { keyType, key } = await detectKeyType(keyData.response);
        result.keyType = keyType;
        result.valid = keyType !== KeyType.Invalid;

        if (key) {
            const identities = await key.getUserIDs();
            result.emailInKey = identities.some(identity => identity.includes(email));
            result.fingerprint = key.getFingerprint().toUpperCase();
        }
    }

    return result;
};

/**
 * Encode input using Z-Base32 encoding.
 *
 * @param {Uint8Array} data - The binary data to encode
 * @returns {String} Binary data encoded using Z-Base32.
 */
function zbase32Encode(data: Uint8Array): string {
    if (data.length === 0) {
        return "";
    }
    const ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
    const SHIFT = 5;
    const MASK = 31;
    let buffer = data[0];
    let index = 1;
    let bitsLeft = 8;
    let result = '';
    while (bitsLeft > 0 || index < data.length) {
        if (bitsLeft < SHIFT) {
            if (index < data.length) {
                buffer <<= 8;
                buffer |= data[index++] & 0xff;
                bitsLeft += 8;
            } else {
                const pad = SHIFT - bitsLeft;
                buffer <<= pad;
                bitsLeft += pad;
            }
        }
        bitsLeft -= SHIFT;
        result += ALPHABET[MASK & (buffer >> bitsLeft)];
    }
    return result;
}

/**
 * Generates WKD URLs for a given email address.
 * @param {string} email - The email address.
 * @returns {Promise<{ advancedUrl: string, directUrl: string, advancedPolicyUrl: string, directPolicyUrl: string }>} The generated URLs.
 */
const generateWkdUrls = async (email: string) => {
    const [localPart, domain] = email.split('@');

    // Spec Requirement: map uppercase ASCII to lowercase. Non-ASCII are not changed.
    const localPartHashInput = localPart.replace(/[A-Z]/g, c => c.toLowerCase());
    const domainLower = domain.toLowerCase();

    const hashBuffer = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(localPartHashInput));

    const hash = zbase32Encode(new Uint8Array(hashBuffer));
    const nameParam = encodeURIComponent(localPart);

    return {
        advancedUrl: `https://openpgpkey.${domainLower}/.well-known/openpgpkey/${domainLower}/hu/${hash}?l=${nameParam}`,
        directUrl: `https://${domainLower}/.well-known/openpgpkey/hu/${hash}?l=${nameParam}`,
        advancedPolicyUrl: `https://openpgpkey.${domainLower}/.well-known/openpgpkey/policy`,
        directPolicyUrl: `https://${domainLower}/.well-known/openpgpkey/policy`
    };
}

/**
 * Search for a public key using Web Key Directory protocol.
 * @param {string} email - User's email.
 * @returns {Promise<Uint8Array>} The public key.
 */
export const getKey = async (email: string): Promise<Uint8Array> => {
    if (!validateEmail(email)) {
        throw new WKDError('Invalid e-mail address.');
    }

    const { advancedUrl, directUrl } = await generateWkdUrls(email);
    const urls = [advancedUrl, directUrl];

    for (const url of urls) {
        try {
            const response = await fetch(url);
            if (response.ok) {
                return new Uint8Array(await response.arrayBuffer());
            }
        } catch {
            // Ignore error and try next URL
        }
    }

    throw new WKDError('No keys found');
}

/**
 * Processes an email to find WKD keys using both Advanced and Direct methods.
 * @param {string} email - The email address to look up.
 * @returns {Promise<{ advanced: KeyCheckResult, direct: KeyCheckResult }>} Results for both lookup methods.
 */
export const checkKey = async (email: string): Promise<{ advanced: KeyCheckResult, direct: KeyCheckResult }> => {
    const { advancedUrl, directUrl, advancedPolicyUrl, directPolicyUrl } = await generateWkdUrls(email);

    const options: RequestInit = {
        headers: { "User-Agent": "WKD-Checker (+https://miarecki.eu/posts/web-key-directory-setup/)" }
    };

    const [advancedResult, directResult] = await Promise.all([
        checkKeyUrl(advancedUrl, advancedPolicyUrl, options, email),
        checkKeyUrl(directUrl, directPolicyUrl, options, email)
    ]);

    return { advanced: advancedResult, direct: directResult };
};
