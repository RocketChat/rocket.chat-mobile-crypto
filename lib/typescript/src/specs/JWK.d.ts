/**
 * An RSA key in JSON Web Key format.
 *
 * @see {@linkcode MobileCrypto.rsaImportKey}
 */
export interface JWK {
    kty: string;
    alg?: string;
    ext?: boolean;
    key_ops?: string[];
    n: string;
    e: string;
    d?: string;
    p?: string;
    q?: string;
    dp?: string;
    dq?: string;
    qi?: string;
}
//# sourceMappingURL=JWK.d.ts.map