import type { AESGCMCiphertext } from './specs/AESGCMCiphertext';
import type { AESKey } from './specs/AESKey.nitro';
import type { EncryptedFile } from './specs/EncryptedFile';
import type { PBKDF2HashAlgorithm } from './specs/PBKDF2HashAlgorithm';
import type { RSAHashAlgorithm } from './specs/RSAHashAlgorithm';
import type { RSAKeyPair } from './specs/RSAKeyPair';
import type { RSAPrivateKey } from './specs/RSAPrivateKey.nitro';
import type { RSAPublicKey } from './specs/RSAPublicKey.nitro';
import type { SHAAlgorithm } from './specs/SHAAlgorithm';
export type { AESGCMCiphertext, AESKey, EncryptedFile, PBKDF2HashAlgorithm, RSAHashAlgorithm, RSAKeyPair, RSAPrivateKey, RSAPublicKey, SHAAlgorithm, };
export declare function sha(data: ArrayBuffer, algorithm: SHAAlgorithm): Promise<ArrayBuffer>;
export declare function hmac256(data: ArrayBuffer, key: ArrayBuffer): Promise<ArrayBuffer>;
export declare function aesGenerateKey(byteLength: number): AESKey;
export declare function aesImportKey(base64Url: string): AESKey;
export interface AESDeriveKeyOptions {
    iterations: number;
    byteLength: number;
    hash: PBKDF2HashAlgorithm;
}
export declare function aesDeriveKey(passwordBase64: string, saltBase64: string, options: AESDeriveKeyOptions): Promise<AESKey>;
export declare function aesGcmEncrypt(key: AESKey, plaintext: string): Promise<AESGCMCiphertext>;
export declare function aesGcmDecrypt(key: AESKey, encrypted: AESGCMCiphertext): Promise<string>;
export declare function aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string>;
export declare function aesCbcDecrypt(key: AESKey, ivAndCiphertext: string): Promise<string>;
export declare function aesEncryptFile(filePath: string): Promise<EncryptedFile>;
export declare function aesDecryptFile(file: EncryptedFile): Promise<string>;
export declare function rsaGenerateKeys(keySize?: number): Promise<RSAKeyPair>;
export declare function rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey>;
export declare function rsaImportPublicKey(jwk: string): Promise<RSAPublicKey>;
export declare function rsaEncrypt(publicKey: RSAPublicKey, plaintext: string): Promise<string>;
export declare function rsaDecrypt(privateKey: RSAPrivateKey, ciphertext: string): Promise<string>;
export declare function rsaSign(privateKey: RSAPrivateKey, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
export declare function rsaVerify(publicKey: RSAPublicKey, signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<boolean>;
export declare function randomUuid(): string;
export declare function randomKey(length: number): string;
export declare function randomBytes(size: number): ArrayBuffer;
//# sourceMappingURL=index.d.ts.map