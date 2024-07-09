import { Signer } from './signer';
import ecdsa from 'secp256k1';

export class skSignerEncrypted implements Signer {
    sk: Uint8Array;

    /**
     * @dev `sk` is an encrypted format of a private key
     * 
     * @param encrypted Private key in hex string format
     */
    constructor(encrypted: string) {
        throw new Error("To be supported in the next version");
    }

    async sign(hash: Buffer): Promise<{
        rc: number,
        signature: Uint8Array
    }> {
        const signature = ecdsa.ecdsaSign(hash, this.sk)
        return {
            rc: signature.recid,
            signature: signature.signature
        };
    }
}