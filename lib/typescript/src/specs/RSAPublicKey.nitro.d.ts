import type { HybridObject } from 'react-native-nitro-modules';
/**
 * An RSA public key held in native memory.
 *
 * @see {@linkcode MobileCrypto.rsaImportPublicKey}
 * @see {@linkcode MobileCrypto.rsaEncrypt}
 * @see {@linkcode MobileCrypto.rsaVerify}
 */
export interface RSAPublicKey extends HybridObject<{
    ios: 'swift';
    android: 'kotlin';
}> {
    /** Returns the key as a JWK JSON string. */
    exportJwk(): string;
}
//# sourceMappingURL=RSAPublicKey.nitro.d.ts.map