import { KMSSigner } from "./KMSSigner";
import { Signer } from "./signer";
import { skSigner } from "./skSigner";
import { SignerType } from "./types";
export {SignerType, Signer, KMSSigner, skSigner};

/**
 * @dev
 * SignerType.SK
 * params: {
 *  sk: string
 * }
 * 
 * SignerType.KMS
 * {
 *  keyId: string,
 *  pk: string
 * }
 * 
 * examples
 * @param signerType 
 * @param params 
 */
export function createSigner(signerType: SignerType, params: any): Signer {
    switch(signerType) {
        case SignerType.SK: {
            if (!params.sk) {
                throw new Error(`param 'sk' is needed`);
            }

            return new skSigner(params.sk);
        };
        break;
        case SignerType.KMS: {
            if (!params.keyId) {
                throw new Error(`param 'keyId' is needed`);
            }

            if (!params.pk) {
                throw new Error(`param 'pk' is needed`);
            }

            return new KMSSigner(params.keyId, params.pk);
        }
        default: throw new Error('Not supported signer type');
    }
}