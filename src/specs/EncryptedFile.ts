/**
 * A file encrypted with AES-256-CTR under a freshly generated key and IV.
 *
 * @see {@linkcode MobileCrypto.aesEncryptFile}
 */
export interface EncryptedFile {
  /** Path of the encrypted copy. */
  path: string;
  /** The key as unpadded base64url, the JWK `k` format. */
  key: string;
  /** The 16-byte IV, base64-encoded. */
  iv: string;
  /** Lowercase hex SHA-256 of the original, unencrypted file. */
  sha256: string;
}
