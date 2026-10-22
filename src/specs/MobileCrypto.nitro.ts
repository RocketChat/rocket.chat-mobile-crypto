import type { HybridObject } from 'react-native-nitro-modules';
import type { JWK } from './JWK';
import type { RSAKeyPair } from './RSAKeyPair';

/**
 * Native hashing, key derivation, symmetric and asymmetric encryption,
 * signing, and secure random generation.
 */
export interface MobileCrypto
  extends HybridObject<{ ios: 'swift'; android: 'kotlin' }> {
  shaBase64(data: string, algorithm: string): Promise<string>;
  shaBase64Sync(data: string, algorithm: string): string;
  shaUtf8(data: string, algorithm: string): Promise<string>;
  shaUtf8Sync(data: string, algorithm: string): string;
  pbkdf2Hash(
    pwdBase64: string,
    saltBase64: string,
    iterations: number,
    keyLen: number,
    hash: string
  ): Promise<string>;
  hmac256(data: string, key: string): Promise<string>;
  hmac256Sync(data: string, key: string): string;
  aesEncrypt(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): Promise<string | undefined>;
  aesEncryptSync(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): string | undefined;
  aesDecrypt(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): Promise<string | undefined>;
  aesDecryptSync(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): string | undefined;
  aesGcmEncrypt(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): Promise<string | undefined>;
  aesGcmEncryptSync(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): string | undefined;
  aesGcmDecrypt(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): Promise<string | undefined>;
  aesGcmDecryptSync(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): string | undefined;
  aesEncryptFile(
    filePath: string,
    base64UrlKey: string,
    base64Iv: string
  ): Promise<string>;
  aesDecryptFile(
    filePath: string,
    base64UrlKey: string,
    base64Iv: string
  ): Promise<string>;
  randomUuid(): string;
  randomKey(length: number): string;
  randomBytes(size: number): string;
  rsaGenerateKeys(keySize?: number): Promise<RSAKeyPair>;
  rsaEncrypt(message: string, publicKey: string): string;
  rsaEncrypt64(message: string, publicKey: string): string;
  rsaDecrypt(encodedMessage: string, privateKey: string): Promise<string>;
  rsaDecrypt64(encodedMessage: string, privateKey: string): Promise<string>;
  rsaSign(message: string, privateKey: string, hash?: string): Promise<string>;
  rsaSign64(
    message: string,
    privateKey: string,
    hash?: string
  ): Promise<string>;
  rsaVerify(
    signature: string,
    message: string,
    publicKey: string,
    hash?: string
  ): Promise<boolean>;
  rsaVerifySync(
    signature: string,
    message: string,
    publicKey: string,
    hash?: string
  ): boolean;
  rsaVerify64(
    signature: string,
    message: string,
    publicKey: string,
    hash?: string
  ): Promise<boolean>;
  rsaVerify64Sync(
    signature: string,
    message: string,
    publicKey: string,
    hash?: string
  ): boolean;
  calculateFileChecksum(filePath: string): Promise<string>;
  getRandomValues(length: number): string;
  rsaImportKey(jwk: JWK): Promise<string>;
  rsaExportKey(pem: string): Promise<JWK>;
}
