import { encode as zbase32Encode } from 'zbase32';
import { Key, readKey } from 'openpgp';

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

export enum KeyType {
    Invalid = 'Invalid',
    BinaryKey = 'BinaryKey',
    ArmoredKey = 'ArmoredKey',
}

const EMAIL_REGEX = /^[^@]+@[^@]+\.[^@]+$/;

export const validateEmail = (email: string): boolean => EMAIL_REGEX.test(email);

const fetchWithCorsCheck = async (url: string, options: RequestInit): Promise<{ response: Response | null, corsValid: boolean }> => {
    try {
        const response = await fetch(url, options);
        const corsValid = response.headers.get("access-control-allow-origin") === "*";
        return { response: response.ok ? response : null, corsValid };
    } catch {
        return { response: null, corsValid: false };
    }
}

const detectKeyType = async (keyData: Response): Promise<{ keyType: KeyType, key: Key | null }> => {
    try {
        const text = await keyData.clone().text();
        if (text.startsWith('-----BEGIN PGP PUBLIC KEY BLOCK-----')) {
            const key = await readKey({ armoredKey: text });
            return { keyType: KeyType.ArmoredKey, key };
        } else {
            const binaryKey = new Uint8Array(await keyData.clone().arrayBuffer());
            const key = await readKey({ binaryKey });
            return { keyType: KeyType.BinaryKey, key };
        }
    } catch {
        return { keyType: KeyType.Invalid, key: null };
    }
}

export const checkKey = async (url: string, policy: string, options: RequestInit, email: string): Promise<KeyCheckResult> => {
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

export const processEmail = async (email: string): Promise<{ advanced: KeyCheckResult, direct: KeyCheckResult }> => {
    const [localPart, domain] = email.split('@');
    const hashBuffer = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(localPart.toLowerCase()));
    const hash = zbase32Encode(hashBuffer);
    const nameParam = encodeURIComponent(localPart);

    const options: RequestInit = {
        headers: { "User-Agent": "WKD-Checker (+https://miarecki.eu/posts/web-key-directory-setup/)" }
    };

    const basicUrl = `https://${domain}/.well-known/openpgpkey/hu/${hash}?l=${nameParam}`;
    const basicPolicyUrl = `https://${domain}/.well-known/openpgpkey/policy`;
    const advancedUrl = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/hu/${hash}?l=${nameParam}`;
    const advancedPolicyUrl = `https://openpgpkey.${domain}/.well-known/openpgpkey/${domain}/policy`;

    const [advancedResult, directResult] = await Promise.all([
        checkKey(advancedUrl, advancedPolicyUrl, options, email),
        checkKey(basicUrl, basicPolicyUrl, options, email)
    ]);

    return { advanced: advancedResult, direct: directResult };
};

export { zbase32Encode };
