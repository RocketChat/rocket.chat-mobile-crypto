/**
 * A PEM-encoded RSA key pair.
 *
 * @see {@linkcode MobileCrypto.rsaGenerateKeys}
 */
export interface RSAKeyPair {
  publicKey: string;
  privateKey: string;
}
