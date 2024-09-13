import { Signer } from './signer';
import { KMS } from '@aws-sdk/client-kms';
import { Sequence, fromBER } from 'asn1js';
import { SignerType } from './types';
import { ecrecover } from 'ethereumjs-util';

const ORDER = Uint8Array.from(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
const HALF_ORDER = Uint8Array.from(Buffer.from('7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0', 'hex'))

// 比较两个 Uint8Array，按字节比较
function compareUint8Array(a: Uint8Array, b: Uint8Array): number {
    for (let i = 0; i < a.length; i++) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

// 减法: n - s
function subtractUint8Array(n: Uint8Array, s: Uint8Array): Uint8Array {
    const result = new Uint8Array(n.length);
    let carry = 0;
    for (let i = n.length - 1; i >= 0; i--) {
        let diff = n[i] - s[i] - carry;
        if (diff < 0) {
            diff += 256;
            carry = 1;
        } else {
            carry = 0;
        }
        result[i] = diff;
    }
    return result;
}

export class KMSSigner implements Signer {
    kms: KMS;
    keyId: string;
    pk: string;

    constructor(keyId: string, pk: string) {
        this.keyId = keyId;
        this.pk = pk;
        this.kms = new KMS();
    }

    private handleDecodedData(data: Buffer): Buffer {
        const asn1 = fromBER(data);
        if (asn1.offset === -1) {
            throw new Error('Failed to decode DER data');
        }

        if (asn1.result.constructor.name === 'Sequence') {
            let buffers: Array<Buffer> = [];
            const sequence = asn1.result as Sequence;
            sequence.valueBlock.value.forEach((element: any) => {
                let valueHex = Buffer.from(element.valueBlock.valueHex);
                if (valueHex.length == 33 && valueHex[0] == 0) {
                    valueHex = valueHex.subarray(1);
                }
                buffers.push(valueHex);
            });
            return Buffer.concat(buffers);
        } else {
            throw new Error('Failed to decode DER data');
        }
    }

    async sign(hash: Buffer): Promise<{
        rc: number,
        signature: Uint8Array
    }> {
        return new Promise((res, rej) => {
            this.kms.sign(
                {
                    KeyId: this.keyId,
                    MessageType: 'DIGEST',
                    Message: Uint8Array.from(hash),
                    SigningAlgorithm: 'ECDSA_SHA_256'
                },
                (err, data) => {
                    if (err) {
                        console.error('err', err);
                        rej(err);
                    } else {
                        let signature = this.handleDecodedData(
                            Buffer.from(data!.Signature!)
                        );
                        const r = signature.subarray(0, 32); // 32 字节的 r 值
                        let s = signature.subarray(32, 64); // 32 字节的 s 值

                        if (compareUint8Array(s, HALF_ORDER) > 0) {
                            s = Buffer.from(subtractUint8Array(ORDER, s));
                        }

                        const pubKeyV0 = ecrecover(hash, 27, r, s);
                        const pubKeyV1 = ecrecover(hash, 28, r, s);
                        
                        let rc = 0;
                        if (this.pk.substring(2) == pubKeyV0.toString('hex')) {
                            rc = 0;
                        }
                        else if (this.pk.substring(2) == pubKeyV1.toString('hex')) {
                            rc = 1;
                        }
                        else {
                            throw new Error("Public key can not be recorved");
                        }

                        res({
                            rc,
                            signature: Buffer.concat([r, s])
                        });
                    }
                }
            );
        });
    }

    /**
     * @notice Returns the public key
     * @param compressed If the public key is compressed
     */
    getPublicKey(compressed: boolean, hex: boolean = false): Uint8Array | string {
        if (!compressed) {
            if (hex) {
                return this.pk;
            }
            else {
                return Uint8Array.from(Buffer.from(this.pk.substring(2), 'hex'));
            }
        }
        else {
            if (hex) {
                return `0x${this.pk.substring(2, 66)}`;
            }
            return Uint8Array.from(Buffer.from(this.pk.substring(2, 66), 'hex'));
        }
    }

    getConfig(): any {
        return {
            signerType: SignerType.KMS,
            params: {
                keyId: this.keyId,
                pk: this.pk
            }
        }
    }
}
