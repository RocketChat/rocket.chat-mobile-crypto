import type { HybridObject } from 'react-native-nitro-modules';
import type { RSAHashAlgorithm } from './RSAHashAlgorithm';
/**
 * A parsed RSA private key that can decrypt and sign without re-reading PEM.
 *
 * @see {@linkcode MobileCrypto.rsaImportPrivateKey}
 */
export interface RSAPrivateKey extends HybridObject<{
    ios: 'swift';
    android: 'kotlin';
}> {
    /** Decrypts RSA-OAEP (SHA-256) ciphertext. */
    decrypt(ciphertext: ArrayBuffer): Promise<ArrayBuffer>;
    /** Creates a PKCS#1 v1.5 signature over `message`. */
    sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
}
//# sourceMappingURL=RSAPrivateKey.nitro.d.ts.map