import { createSigner } from "../src";
import { SignerType } from "../src/types";

const SK = '0x1234567812345678123456781234567812345678123456781234567812345678';
const PK = '0xeb31fbe78fc743f6f8ba04ce27791685c2152bdbacf020696c7086a95d353eb0d057c808f233f6f7ababe98e554fcb815dd39ee7043332a6733d63972145e955';

describe('Signer', function () {
    describe('Create sk signer', function () {
        it('should fail with lacking of parameters', () => {
            expect(() => {createSigner(SignerType.SK, {})}).toThrow("param 'sk' is needed");
        });

        it('should pass with parameters right', () => {
            createSigner(SignerType.SK, {sk: "0x1234567812345678123456781234567812345678123456781234567812345678"});
        });
    });

    describe('Get public key', function () {
        const signer = createSigner(SignerType.SK, {
            sk: SK
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