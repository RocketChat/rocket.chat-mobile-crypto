import type { HybridObject } from 'react-native-nitro-modules';
/**
 * An RSA private key held in native memory.
 *
 * @see {@linkcode MobileCrypto.rsaImportPrivateKey}
 * @see {@linkcode MobileCrypto.rsaDecrypt}
 * @see {@linkcode MobileCrypto.rsaSign}
 */
export interface RSAPrivateKey extends HybridObject<{
    ios: 'swift';
    android: 'kotlin';
}> {
    /** Returns the key as a JWK JSON string. */
    exportJwk(): string;
}
//# sourceMappingURL=RSAPrivateKey.nitro.d.ts.map