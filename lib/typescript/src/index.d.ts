import type { AESGCMCiphertext } from './specs/AESGCMCiphertext';
import type { AESKey } from './specs/AESKey.nitro';
import type { EncryptedFile } from './specs/EncryptedFile';
import type { PBKDF2HashAlgorithm } from './specs/PBKDF2HashAlgorithm';
import type { RSAHashAlgorithm } from './specs/RSAHashAlgorithm';
import type { SHAAlgorithm } from './specs/SHAAlgorithm';
export interface RSAPrivateKey {
    decrypt(ciphertext: string): Promise<string>;
    sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
    exportJwk(): string;
}
export interface RSAPublicKey {
    encrypt(plaintext: string): Promise<string>;
    verify(signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<boolean>;
    exportJwk(): string;
}
export interface RSAKeyPair {
    publicKey: RSAPublicKey;
    privateKey: RSAPrivateKey;
}
export type { AESGCMCiphertext, AESKey, EncryptedFile, PBKDF2HashAlgorithm, RSAHashAlgorithm, SHAAlgorithm, };
export declare function sha(data: ArrayBuffer, algorithm: SHAAlgorithm): Promise<ArrayBuffer>;
export declare function hmac256(data: ArrayBuffer, key: ArrayBuffer): Promise<ArrayBuffer>;
export declare function aesGenerateKey(byteLength: number): AESKey;
export declare function aesImportKey(base64Url: string): AESKey;
export declare function aesDeriveKey(passwordBase64: string, saltBase64: string, iterations: number, byteLength: number, hash: PBKDF2HashAlgorithm): Promise<AESKey>;
export declare function aesGcmEncrypt(key: AESKey, plaintext: string): Promise<AESGCMCiphertext>;
export declare function aesGcmDecrypt(key: AESKey, ciphertext: string, iv: string): Promise<string>;
export declare function aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string>;
export declare function aesCbcDecrypt(key: AESKey, ivAndCiphertext: string): Promise<string>;
export declare function aesEncryptFile(filePath: string): Promise<EncryptedFile>;
export declare function aesDecryptFile(filePath: string, key: string, iv: string, sha256: string): Promise<string>;
export declare function rsaGenerateKeys(keySize?: number): Promise<RSAKeyPair>;
export declare function rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey>;
export declare function rsaImportPublicKey(jwk: string): Promise<RSAPublicKey>;
export declare function randomUuid(): string;
export declare function randomKey(length: number): string;
export declare function randomBytes(size: number): ArrayBuffer;
//# sourceMappingURL=index.d.ts.map