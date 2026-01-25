import { Key, readKey } from 'openpgp';

/**
 * Result of a key check operation.
 */
export interface KeyCheckResult {
    policy_location: string;
    policyAvailable: boolean;
    policyCorsValid: boolean;
    key_location: string | null;
    key_available: boolean;
    keyCorsValid: boolean;
    keyType: KeyType;
    keyTypeValid: boolean;
    fingerprint: string | null;
    emailInKey: boolean;
    expired: boolean;
    revoked: boolean;
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
const USER_AGENT = "WKD-Checker (+https://www.npmjs.com/package/wkd-checker)";

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

        // Spec does not mandate CORS, but it is beneficial for web clients (e.g. webmail usage). Not factored into validity.
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

        // Spec Section 3.1: "The server SHOULD use "application/octet-stream" as the Content-Type for the data but clients SHOULD also accept any other Content-Type. The server SHOULD NOT return an ASCII armored version of the key."
        if (prefix === header) {
            const text = new TextDecoder().decode(binaryKey);
            const key = await readKey({ armoredKey: text });
            return { keyType: KeyType.ArmoredKey, key };
        } else {
            // Spec Section 3.1: "The HTTP GET method MUST return the binary representation of the OpenPGP key for the given mail address."
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
        policy_location: policyData.response?.url || policy,
        policyAvailable: !!policyData.response,
        policyCorsValid: policyData.corsValid,
        key_location: keyData.response?.url || url,
        key_available: !!keyData.response,
        keyCorsValid: keyData.corsValid,
        keyType: KeyType.Invalid,
        keyTypeValid: false,
        fingerprint: null,
        emailInKey: false,
        expired: false,
        revoked: false,
        valid: false,
    };

    if (keyData.response) {
        const { keyType, key } = await detectKeyType(keyData.response);
        result.keyType = keyType;

        // The HTTP GET method MUST return the binary representation of the OpenPGP key for the given mail address.
        result.keyTypeValid = keyType === KeyType.BinaryKey

        if (key) {
            const identities = await key.getUserIDs();

            // Spec Section 5: "The mail provider MUST make sure to publish a key in a way that only the mail address belonging to the requested user is part of the User ID packets included in the returned key."
            // "Other User ID packets and their associated binding signatures MUST be removed before publication."
            result.emailInKey = identities.length > 0;
            for (const id of identities) {
                const match = id.match(/<(.+)>/);
                const emailInId = match ? match[1] : id;
                if (emailInId.trim() !== email) {
                    result.emailInKey = false;
                    break;
                }
            }

            result.fingerprint = key.getFingerprint().toUpperCase();

            const expirationTime = await key.getExpirationTime();
            if (expirationTime !== Infinity && expirationTime !== null) {
                result.expired = expirationTime < new Date();
            }

            result.revoked = await key.isRevoked();
        }
    }

    result.valid = result.policyAvailable &&
        result.key_available &&
        result.keyTypeValid &&
        result.emailInKey;

    return result;

};

/**
 * Encode input using Z-Base32 encoding.
 * 
 * Spec Section 3.1: "The resulting 160 bit digest is encoded using the Z-Base-32 method as described in [RFC6189], section 5.1.6."
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
 * Spec Section 3.1: "Key Discovery"
 * @param {string} email - The email address.
 * @returns {Promise<{ advancedUrl: string, directUrl: string, advancedPolicyUrl: string, directPolicyUrl: string }>} The generated URLs.
 */
const generateWkdUrls = async (email: string) => {
    const [localPart, domain] = email.split('@');

    // Spec Section 3.1: "all upper-case ASCII characters in a User ID are mapped to lowercase. Non-ASCII characters are not changed."
    const localPartHashInput = localPart.replace(/[A-Z]/g, c => c.toLowerCase());
    const domainLower = domain.toLowerCase();

    // Spec Section 3.1: "The so mapped local-part is hashed using the SHA-1 algorithm."
    const hashBuffer = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(localPartHashInput));

    // Spec Section 3.1: "The resulting 160 bit digest is encoded using the Z-Base-32 method as described in [RFC6189], section 5.1.6.  The resulting string has a fixed length of 32 octets."
    const hash = zbase32Encode(new Uint8Array(hashBuffer));
    const nameParam = encodeURIComponent(localPart);

    return {
        // Spec Section 3.1: Advanced Method URI Construction
        advancedUrl: `https://openpgpkey.${domainLower}/.well-known/openpgpkey/${domainLower}/hu/${hash}?l=${nameParam}`,
        // Spec Section 3.1: Direct Method URI Construction
        directUrl: `https://${domainLower}/.well-known/openpgpkey/hu/${hash}?l=${nameParam}`,
        // Spec Section 4.5: Policy Flags
        advancedPolicyUrl: `https://openpgpkey.${domainLower}/.well-known/openpgpkey/${domainLower}/policy`,
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
    // Spec Section 3.1: "Implementations MUST first try the advanced method. Only if an address for the required sub-domain does not exist, they SHOULD fall back to the direct method."
    const urls = [advancedUrl, directUrl];

    for (const url of urls) {
        try {
            const response = await fetch(url, { headers: { 'User-Agent': USER_AGENT } });
            if (response.ok) {
                // Spec Section 3.1
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
        headers: { "User-Agent": USER_AGENT }
    };

    const [advancedResult, directResult] = await Promise.all([
        checkKeyUrl(advancedUrl, advancedPolicyUrl, options, email),
        checkKeyUrl(directUrl, directPolicyUrl, options, email)
    ]);

    return { advanced: advancedResult, direct: directResult };
};
