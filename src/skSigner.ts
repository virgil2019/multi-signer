import { Signer } from './signer';
import ecdsa from 'secp256k1';
import { SignerType } from './types';

export class skSigner implements Signer {
    sk: Uint8Array;

    /**
     * @dev `sk` is the private key in the hex string format
     * 
     * @param key Private key in hex string format
     */
    constructor(key: string) {
        if (key.substring(0, 2) == '0x') {
            if (key.length != 66) {
                throw new Error(`Private key length error`);
            }
            else {
                this.sk = Buffer.from(key.substring(2), 'hex');
            }
        }
        else {
            if (key.length != 64) {
                throw new Error(`Private key length error`);
            }
            else {
                this.sk = Buffer.from(key, 'hex');
            }
        }
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

    getPublicKey(compressed: boolean, hex: boolean = false): Uint8Array | string {
        const pk = ecdsa.publicKeyCreate(this.sk, compressed).subarray(1);
        if (hex) {
            return `0xBuffer.from(pk).toString('hex')`;
        }
        else {
            return pk;
        }
    }

    getConfig(): any {
        return {
            signerType: SignerType.SK,
            params: {
                sk: `0x${Buffer.from(this.sk).toString('hex')}`
            }
        }
    }
}