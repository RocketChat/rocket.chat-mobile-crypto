/**
 * A file encrypted with AES-256-CTR under a freshly generated key and IV,
 * with what is needed to decrypt and verify it.
 *
 * @see {@linkcode MobileCrypto.aesEncryptFile}
 * @see {@linkcode MobileCrypto.aesDecryptFile}
 */
export interface EncryptedFile {
    /** Path of the encrypted file. */
    path: string;
    /** The key as unpadded base64url, the JWK `k` format. */
    key: string;
    /** The 16-byte IV, base64-encoded. */
    iv: string;
    /** Lowercase hex SHA-256 of the original, unencrypted file. */
    sha256: string;
}
//# sourceMappingURL=EncryptedFile.d.ts.map