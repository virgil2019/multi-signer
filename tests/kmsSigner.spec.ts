import { createSigner } from "../src";
import { SignerType } from "../src/types";

const PK = '0x1befc9021b51ee768110d3b579fac51ceaf4192880b5f34409d9cfb2aa55649bd4443c3ca5762020d75d8f05202ac61d8230679ace5f10d7d37b51149e0d0d55';

describe('KMS Signer', function () {
    describe('construct', function () {
        it('should pass', () => {
            const signer = createSigner(SignerType.KMS, {
                keyId: "KEYID",
                pk: PK
            });
        });
    });

    describe('sign', function () {
        it('should fail with the hash param not 32 bytes', async () => {
            const signer = createSigner(SignerType.KMS, {
                keyId: "KEYID",
                pk: PK
            });

            try {
                const message = Buffer.from('12345678');
                expect(message.length).toBeLessThan(32);
                await signer.sign(message);
                throw 'It should throw';
            } catch (e) {}

            try {
                const message = Buffer.from(
                    '123456781234567812345678123456781234567812345678'
                );
                expect(message.length).toBeGreaterThan(32);
                await signer.sign(message);
                throw 'It should throw';
            } catch (e) {}
        });

        it('should work with the message is 32 bytes', async () => {
            const signer = createSigner(SignerType.KMS, {
            keyId: "KEYID",
            pk: PK
        });
            const message = Buffer.from('12345678123456781234567812345678');
            expect(message.length).toBe(32);
            const sig = await signer.sign(message);
            expect(sig.signature.length).toBeGreaterThan(0);
        });
    });

    describe('Get public key', function () {
        const signer = createSigner(SignerType.KMS, {
            keyId: "KEYID",
            pk: PK
        });

        it('should pass when getting uncompressed public key with hex format ', () => {
            expect(signer.getPublicKey(false, true)).toEqual(PK);
        });

        it('should pass when getting uncompressed public key with uint8array format ', () => {
            expect(signer.getPublicKey(false, false)).toEqual(Uint8Array.from(Buffer.from(PK.substring(2), 'hex')));
        });

        it('should pass when getting compressed public key with hex format ', () => {
            expect(signer.getPublicKey(true, true)).toEqual(`0x${PK.substring(2, 66)}`);
        });

        it('should pass when getting compressed public key with uint8array format ', () => {
            expect(signer.getPublicKey(true, false)).toEqual(Uint8Array.from(Buffer.from(PK.substring(2, 66), 'hex')));
        });
    });
});