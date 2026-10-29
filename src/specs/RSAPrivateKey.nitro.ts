import type { HybridObject } from 'react-native-nitro-modules';
import type { RSAHashAlgorithm } from './RSAHashAlgorithm';

/**
 * An RSA private key held in native memory.
 *
 * @see {@linkcode MobileCrypto.rsaImportPrivateKey}
 */
export interface RSAPrivateKey
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  /** Decrypts base64 RSA-OAEP (SHA-256) ciphertext into a UTF-8 string. */
  decrypt(ciphertext: string): Promise<string>;
  /** Creates a PKCS#1 v1.5 signature over `message`. */
  sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
  /** Returns the key as a JWK JSON string. */
  exportJwk(): string;
}
