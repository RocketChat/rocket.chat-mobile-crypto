/**
 * The output of AES-GCM encryption, with both fields base64-encoded.
 * `ciphertext` ends with the 16-byte authentication tag.
 *
 * @see {@linkcode MobileCrypto.aesGcmEncrypt}
 */
export interface AESGCMCiphertext {
  iv: string;
  ciphertext: string;
}
