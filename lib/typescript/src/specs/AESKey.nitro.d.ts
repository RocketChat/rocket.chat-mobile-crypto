import type { HybridObject } from 'react-native-nitro-modules';
/**
 * An AES key held in native memory. JavaScript keeps a handle to it and
 * never sees the key bytes.
 *
 * @see {@linkcode MobileCrypto.aesGenerateKey}
 * @see {@linkcode MobileCrypto.aesImportKey}
 * @see {@linkcode MobileCrypto.aesDeriveKey}
 */
export interface AESKey extends HybridObject<{
    ios: 'swift';
    android: 'kotlin';
}> {
    /** Returns the key bytes as unpadded base64url, the JWK `k` format. */
    exportBase64Url(): string;
}
//# sourceMappingURL=AESKey.nitro.d.ts.map