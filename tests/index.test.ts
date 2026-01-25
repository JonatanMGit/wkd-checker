import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';
import nock from 'nock';
import * as openpgp from 'openpgp';

import { checkKey, getKey, KeyType } from '../src';

const DOMAIN = 'example.localhost';
const ADVANCED_DOMAIN = 'openpgpkey.example.localhost';

const HASHES = {
    'valid@example.localhost': 'z5bgfyrx9wa8cc8i4fu5s6ixeh8kzxum',
    'ascii-armored@example.localhost': 'c656g9ktx4gbf6g6bse6xwxhuje9dwr4',
    'userid@example.localhost': 'egzj1raewu6jbagu1woqd4p9o8ryf8wq',
    'non-existent@example.localhost': 'rhjk9tb3rtmgayezfgs776occrg1s58a',
    'expired@example.localhost': 'esuxumpt5h78tkzhqrhta9j59j5eyew5',
    'no-encryption@example.localhost': 'sgn3ordw93xzetk8ufjszpkcb5jwojw4',
    'revoked@example.localhost': 'op4h5huitu4e38r4sfydr4647haxmfyg',
    'advanced@example.localhost': 'hawfepwtu8mfs4ug3sex7yoditgizauc',
    'advanced-nonexistent@example.localhost': 'u6hfrjex6tigiakd6nfaoajgfinzpfui'
};

const readKeyFile = (filename: string) => {
    try {
        return fs.readFileSync(path.join(__dirname, 'keys', filename));
    } catch (e) {
        return Buffer.from('');
    }
};

describe('WKD Checker', () => {

    // Catch all requests
    before(() => {
        nock.disableNetConnect();
    });

    after(() => {
        nock.enableNetConnect();
        nock.cleanAll();
    });

    describe('checkKey', () => {

        it('should validate a correct binary key via direct method', async () => {
            const email = 'valid@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('valid.bin');

            // Advanced method fails
            nock(`https://${ADVANCED_DOMAIN}`)
                .get(`/.well-known/openpgpkey/${DOMAIN}/policy`)
                .reply(404)
                .get(`/.well-known/openpgpkey/${DOMAIN}/hu/${hash}`)
                .query(true) // match any query params like l=...
                .reply(404);

            // Direct method succeeds
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, '') // Policy exists
                .get(`/.well-known/openpgpkey/hu/${hash}`)
                .query(true)
                .reply(200, keyBuffer, { 'Content-Type': 'application/octet-stream' });

            const result = await checkKey(email);

            assert.strictEqual(result.direct.valid, true, 'Direct result should be valid');
            assert.strictEqual(result.direct.keyType, KeyType.BinaryKey);
            assert.strictEqual(result.direct.emailInKey, true);

            assert.strictEqual(result.advanced.valid, false, 'Advanced result should be invalid');
        });

        it('should fail validation for ascii armored key', async () => {
            const email = 'ascii-armored@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            // Should verify we are sending armor content, assuming 'ascii-armored.asc' contains armor
            const keyText = readKeyFile('ascii-armored.asc').toString();

            nock(`https://${ADVANCED_DOMAIN}`)
                .get(`/.well-known/openpgpkey/${DOMAIN}/policy`)
                .reply(404)
                .get(`/.well-known/openpgpkey/${DOMAIN}/hu/${hash}`).query(true).reply(404);

            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, '')
                .get(`/.well-known/openpgpkey/hu/${hash}`)
                .query(true)
                .reply(200, keyText, { 'Content-Type': 'text/plain' });

            const result = await checkKey(email);

            assert.strictEqual(result.direct.keyType, KeyType.ArmoredKey);
            assert.strictEqual(result.direct.keyTypeValid, false, 'Armored key should be invalid for WKD');
            assert.strictEqual(result.direct.valid, false);
        });

        it('should fail if User ID does not match', async () => {
            const email = 'userid@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            // This key should have a different email or >= 2 IDs
            const keyBuffer = readKeyFile('userid.bin');

            nock(`https://${ADVANCED_DOMAIN}`)
                .get(`/.well-known/openpgpkey/${DOMAIN}/policy`)
                .reply(404)
                .get(`/.well-known/openpgpkey/${DOMAIN}/hu/${hash}`).query(true).reply(404);

            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, '')
                .get(`/.well-known/openpgpkey/hu/${hash}`)
                .query(true)
                .reply(200, keyBuffer);

            const result = await checkKey(email);

            assert.strictEqual(result.direct.emailInKey, false, 'Email should not match');
            assert.strictEqual(result.direct.valid, false);
        });

        it('should handle non-existent key', async () => {
            const email = 'non-existent@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];

            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);
            nock(`https://${DOMAIN}`).get(/.*/).query(true).reply(404);

            const result = await checkKey(email);

            assert.strictEqual(result.direct.key_available, false);
            assert.strictEqual(result.direct.valid, false);
        });

        it('should return valid true for expired key (WKD transport valid)', async () => {
            // "The key may be revoked or expired - it is up to the client to handle such conditions."
            const email = 'expired@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('expired.bin');

            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`).reply(200, '')
                .get(`/.well-known/openpgpkey/hu/${hash}`).query(true).reply(200, keyBuffer);

            const result = await checkKey(email);

            // Assuming checks are purely transport and structure compliance
            assert.strictEqual(result.direct.keyType, KeyType.BinaryKey);
            assert.strictEqual(result.direct.valid, true);
            assert.strictEqual(result.direct.expired, true, "Key should be marked as expired");
        });

        it('should return valid true for no-encryption key', async () => {
            const email = 'no-encryption@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('no-encryption.bin');

            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`).reply(200, '')
                .get(`/.well-known/openpgpkey/hu/${hash}`).query(true).reply(200, keyBuffer);

            const result = await checkKey(email);

            assert.strictEqual(result.direct.valid, true);
        });

        it('should return valid true for revoked key (WKD transport valid)', async () => {
            const email = 'revoked@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('revoked.bin');

            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`).reply(200, '')
                .get(`/.well-known/openpgpkey/hu/${hash}`).query(true).reply(200, keyBuffer);

            const result = await checkKey(email);

            assert.strictEqual(result.direct.valid, true);
            assert.strictEqual(result.direct.revoked, true, "Key should be marked as revoked");
        });

        it('should validate a correct binary key via advanced method', async () => {
            const email = 'advanced@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('advanced.bin');

            // Advanced method succeeds
            nock(`https://${ADVANCED_DOMAIN}`)
                .get(`/.well-known/openpgpkey/${DOMAIN}/policy`)
                .reply(200, '')
                .get(`/.well-known/openpgpkey/${DOMAIN}/hu/${hash}`)
                .query(true) // match any query params like l=...
                .reply(200, keyBuffer);

            // Direct method 404 (or not called if optimized, but here we call Promise.all)
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(404)
                .get(`/.well-known/openpgpkey/hu/${hash}`)
                .query(true)
                .reply(404);

            const result = await checkKey(email);

            assert.strictEqual(result.advanced.valid, true, 'Advanced result should be valid');
            assert.strictEqual(result.advanced.keyType, KeyType.BinaryKey);
            assert.strictEqual(result.advanced.emailInKey, true);

            assert.strictEqual(result.direct.valid, false, 'Direct result should be invalid when not found');
            assert.strictEqual(result.direct.key_available, false, 'Direct key should not be available');
        });

        it('should return valid for both advanced and direct methods when both exist', async () => {
            const email = 'valid@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('valid.bin');

            // Advanced method succeeds
            nock(`https://${ADVANCED_DOMAIN}`)
                .get(`/.well-known/openpgpkey/${DOMAIN}/policy`)
                .reply(200, '')
                .get(`/.well-known/openpgpkey/${DOMAIN}/hu/${hash}`)
                .query(true)
                .reply(200, keyBuffer);

            // Direct method also succeeds
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, '')
                .get(`/.well-known/openpgpkey/hu/${hash}`)
                .query(true)
                .reply(200, keyBuffer);

            const result = await checkKey(email);

            assert.strictEqual(result.advanced.valid, true, 'Advanced result should be valid');
            assert.strictEqual(result.advanced.keyType, KeyType.BinaryKey);

            assert.strictEqual(result.direct.valid, true, 'Direct result should be valid');
            assert.strictEqual(result.direct.keyType, KeyType.BinaryKey);
        });

        it('should fail policy check if mailbox-only policy is set but key has User Name', async () => {
            const email = 'valid@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('valid.bin');

            // Policy with mailbox-only
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, 'mailbox-only\n')
                .get(`/.well-known/openpgpkey/hu/${hash}`)
                .query(true) // match l=...
                .reply(200, keyBuffer, { 'Content-Type': 'application/octet-stream' });

            // Advanced fail
            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);

            const result = await checkKey(email);

            assert.strictEqual(result.direct.valid, false, 'Should be invalid due to policy');
            assert.strictEqual(result.direct.policyCompliant, false, 'Policy compliant should be false');
            assert.strictEqual(result.direct.policy?.mailboxOnly, true, 'mailbox-only flag should be set');
        });

        it('should pass policy check if mailbox-only policy is set and key has no User Name', async () => {
            // Generate key on fly
            const email = 'mailboxonly@example.localhost';

            const { publicKey } = await openpgp.generateKey({
                userIDs: [{ email }], // No name
                format: 'binary'
            });

            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, 'mailbox-only\n')
                .get(/\/hu\/.*/)
                .query(true)
                .reply(200, Buffer.from(publicKey));

            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);

            const result = await checkKey(email);

            assert.strictEqual(result.direct.valid, true, 'Should be valid');
            assert.strictEqual(result.direct.policyCompliant, true);
        });

        it('should parse complex policy file correctly', async () => {
            const email = 'valid@example.localhost';
            const hash = HASHES[email];
            const keyBuffer = readKeyFile('valid.bin');

            const policy = `mailbox-only
                             # Comment
                             AuTh-submIt
                             protoCOL-vERSion: 42
                             unknown-flag
                             custom-domain_setting: yes`;

            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/policy`)
                .reply(200, policy)
                .get(`/.well-known/openpgpkey/hu/${hash}`).query(true).reply(200, keyBuffer);

            // Advanced fail
            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);

            const result = await checkKey(email);

            assert.ok(result.direct.policy);
            assert.strictEqual(result.direct.policy?.mailboxOnly, true);
            assert.strictEqual(result.direct.policy?.authSubmit, true);
            assert.strictEqual(result.direct.policy?.protocolVersion, 42);

            // Check valid.bin fails mailbox-only
            assert.strictEqual(result.direct.policyCompliant, false);
        });

    });

    describe('getKey', () => {
        it('should return key buffer if found (Direct)', async () => {
            const email = 'valid@example.localhost';
            const hash = HASHES[email as keyof typeof HASHES];
            const keyBuffer = readKeyFile('valid.bin');

            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);
            nock(`https://${DOMAIN}`)
                .get(`/.well-known/openpgpkey/hu/${hash}`).query(true).reply(200, keyBuffer);

            const key = await getKey(email);
            assert.ok(key instanceof Uint8Array);
            assert.ok(key.length > 0);
        });

        it('should throw if no keys found', async () => {
            const email = 'non-existent@example.localhost';
            nock(`https://${ADVANCED_DOMAIN}`).get(/.*/).query(true).reply(404);
            nock(`https://${DOMAIN}`).get(/.*/).query(true).reply(404);

            await assert.rejects(async () => {
                await getKey(email);
            }, /No keys found/);
        });
    });
});

