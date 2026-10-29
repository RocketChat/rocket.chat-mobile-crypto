import type { HybridObject } from 'react-native-nitro-modules';
import type { RSAHashAlgorithm } from './RSAHashAlgorithm';

/**
 * An RSA public key held in native memory.
 *
 * @see {@linkcode MobileCrypto.rsaImportPublicKey}
 */
export interface RSAPublicKey
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  /** Encrypts a UTF-8 string with RSA-OAEP (SHA-256) into base64 ciphertext. */
  encrypt(plaintext: string): string;
  /** Checks a PKCS#1 v1.5 `signature` over `message`. */
  verify(
    signature: ArrayBuffer,
    message: ArrayBuffer,
    hash: RSAHashAlgorithm
  ): boolean;
  /** Returns the key as a JWK JSON string. */
  exportJwk(): string;
}
