import type { HybridObject } from 'react-native-nitro-modules';
import type { AESGCMCiphertext } from './AESGCMCiphertext';
import type { AESKey } from './AESKey.nitro';
import type { EncryptedFile } from './EncryptedFile';
import type { PBKDF2HashAlgorithm } from './PBKDF2HashAlgorithm';
import type { RSAHashAlgorithm } from './RSAHashAlgorithm';
import type { RSAKeyPair } from './RSAKeyPair';
import type { RSAPrivateKey } from './RSAPrivateKey.nitro';
import type { RSAPublicKey } from './RSAPublicKey.nitro';
import type { SHAAlgorithm } from './SHAAlgorithm';
/**
 * Native hashing, key derivation, symmetric and asymmetric encryption,
 * signing, and secure random generation.
 *
 * Strings that carry bytes are base64, except where noted. Plaintext strings
 * are UTF-8.
 */
export interface MobileCrypto extends HybridObject<{
    ios: 'swift';
    android: 'kotlin';
}> {
    sha(data: ArrayBuffer, algorithm: SHAAlgorithm): Promise<ArrayBuffer>;
    shaSync(data: ArrayBuffer, algorithm: SHAAlgorithm): ArrayBuffer;
    hmac256(data: ArrayBuffer, key: ArrayBuffer): Promise<ArrayBuffer>;
    hmac256Sync(data: ArrayBuffer, key: ArrayBuffer): ArrayBuffer;
    aesGenerateKey(byteLength: number): AESKey;
    aesImportKey(base64Url: string): AESKey;
    aesDeriveKey(passwordBase64: string, saltBase64: string, iterations: number, byteLength: number, hash: PBKDF2HashAlgorithm): Promise<AESKey>;
    aesGcmEncrypt(key: AESKey, plaintext: string): Promise<AESGCMCiphertext>;
    aesGcmEncryptSync(key: AESKey, plaintext: string): AESGCMCiphertext;
    aesGcmDecrypt(key: AESKey, encrypted: AESGCMCiphertext): Promise<string>;
    aesGcmDecryptSync(key: AESKey, encrypted: AESGCMCiphertext): string;
    aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string>;
    aesCbcEncryptSync(key: AESKey, plaintext: string): string;
    aesCbcDecrypt(key: AESKey, ivAndCiphertext: string): Promise<string>;
    aesCbcDecryptSync(key: AESKey, ivAndCiphertext: string): string;
    aesEncryptFile(filePath: string): Promise<EncryptedFile>;
    aesDecryptFile(file: EncryptedFile): Promise<string>;
    rsaGenerateKeys(keySize?: number): Promise<RSAKeyPair>;
    rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey>;
    rsaImportPublicKey(jwk: string): Promise<RSAPublicKey>;
    /** Encrypts a UTF-8 string with RSA-OAEP (SHA-256) into base64 ciphertext. */
    rsaEncrypt(publicKey: RSAPublicKey, plaintext: string): string;
    /** Decrypts base64 RSA-OAEP (SHA-256) ciphertext into a UTF-8 string. */
    rsaDecrypt(privateKey: RSAPrivateKey, ciphertext: string): Promise<string>;
    /** Creates a PKCS#1 v1.5 signature over `message`. */
    rsaSign(privateKey: RSAPrivateKey, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
    /** Checks a PKCS#1 v1.5 `signature` over `message`. */
    rsaVerify(publicKey: RSAPublicKey, signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): boolean;
    randomUuid(): string;
    randomKey(length: number): string;
    randomBytes(size: number): ArrayBuffer;
}
//# sourceMappingURL=MobileCrypto.nitro.d.ts.map