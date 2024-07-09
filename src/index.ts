import { Signer } from "./signer";
import { skSigner } from "./skSigner";
import { SignerType } from "./types";
export {SignerType, Signer};

/**
 * @dev
 * SignerType.SK
 * params: {
 *  sk: string
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
        }
        default: throw new Error('Not supported signer type');
    }
}