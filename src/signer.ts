export interface Signer {
    /**
     * @notice Signs a 32-bytes message
     * @return {Buffer} 32-bytes-length message hash
     */
    sign(hash: Buffer): Promise<{
        rc: number,
        signature: Uint8Array
    }>;

    /**
     * @notice Returns the public key
     * @param compressed If the public key is compressed
     */
    getPublicKey(compressed: boolean): Uint8Array;

    getConfig(): any;
}
