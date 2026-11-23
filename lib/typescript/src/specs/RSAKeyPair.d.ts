import type { RSAPrivateKey } from './RSAPrivateKey.nitro';
import type { RSAPublicKey } from './RSAPublicKey.nitro';
/**
 * A freshly generated RSA key pair.
 *
 * @see {@linkcode MobileCrypto.rsaGenerateKeys}
 */
export interface RSAKeyPair {
    publicKey: RSAPublicKey;
    privateKey: RSAPrivateKey;
}
//# sourceMappingURL=RSAKeyPair.d.ts.map