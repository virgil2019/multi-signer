import { createSigner } from "../src";
import { SignerType } from "../src/types";


describe('Signer', function () {
    describe('Create sk signer', function () {
        it('should fail with lacking of parameters', () => {
            expect(() => {createSigner(SignerType.SK, {})}).toThrow("param 'sk' is needed");
        });

        it('should pass with parameters right', () => {
            createSigner(SignerType.SK, {sk: "0x1234567812345678123456781234567812345678123456781234567812345678"});
        });
    });
});