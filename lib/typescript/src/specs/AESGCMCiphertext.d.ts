/**
 * The output of AES-GCM encryption, with both fields base64-encoded.
 * `ciphertext` ends with the 16-byte authentication tag.
 *
 * @see {@linkcode MobileCrypto.aesGcmEncrypt}
 * @see {@linkcode MobileCrypto.aesGcmDecrypt}
 */
export interface AESGCMCiphertext {
    iv: string;
    ciphertext: string;
}
//# sourceMappingURL=AESGCMCiphertext.d.ts.map