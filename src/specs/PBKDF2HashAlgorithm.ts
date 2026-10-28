/**
 * The HMAC digest used as the PBKDF2 pseudo-random function.
 *
 * @see {@linkcode MobileCrypto.pbkdf2Hash}
 */
export type PBKDF2HashAlgorithm =
  | 'SHA1'
  | 'SHA224'
  | 'SHA256'
  | 'SHA384'
  | 'SHA512';
