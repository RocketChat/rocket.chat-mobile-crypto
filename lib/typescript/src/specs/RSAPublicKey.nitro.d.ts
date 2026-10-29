import type { HybridObject } from 'react-native-nitro-modules';
import type { RSAHashAlgorithm } from './RSAHashAlgorithm';
/**
 * A parsed RSA public key that can encrypt and verify without re-reading PEM.
 *
 * @see {@linkcode MobileCrypto.rsaImportPublicKey}
 */
export interface RSAPublicKey extends HybridObject<{
    ios: 'swift';
    android: 'kotlin';
}> {
    /** Encrypts `plaintext` with RSA-OAEP (SHA-256). */
    encrypt(plaintext: ArrayBuffer): ArrayBuffer;
    /** Checks a PKCS#1 v1.5 `signature` over `message`. */
    verify(signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): boolean;
}
//# sourceMappingURL=RSAPublicKey.nitro.d.ts.map