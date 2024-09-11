import { Signer } from './signer';
import { KMS } from '@aws-sdk/client-kms';
import { Sequence, fromBER } from 'asn1js';

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
                        rej(err);
                    } else {
                        let signature = this.handleDecodedData(
                            Buffer.from(data!.Signature!)
                        );
                        res({
                            rc: signature.at(64)!,
                            signature: signature.subarray(0, 64)
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
    getPublicKey(compressed: boolean): Uint8Array {
        if (!compressed) {
            return Uint8Array.from(Buffer.from(this.pk.substring(2), 'hex'));
        }
        else {
            return Uint8Array.from(Buffer.from(this.pk.substring(2, 64), 'hex'));
        }
    }
}
