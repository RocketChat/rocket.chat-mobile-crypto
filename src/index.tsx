import MobileCrypto, { type JWK } from './NativeMobileCrypto';

// Export the JWK type for users
export type { JWK };

export function shaBase64(data: string, algorithm: string): Promise<string> {
  return MobileCrypto.shaBase64(data, algorithm);
}

export function shaUtf8(data: string, algorithm: string): Promise<string> {
  return MobileCrypto.shaUtf8(data, algorithm);
}

export function pbkdf2Hash(
  pwdBase64: string,
  saltBase64: string,
  iterations: number,
  keyLen: number,
  hash: string
): Promise<string> {
  return MobileCrypto.pbkdf2Hash(
    pwdBase64,
    saltBase64,
    iterations,
    keyLen,
    hash
  );
}

export function hmac256(data: string, key: string): Promise<string> {
  return MobileCrypto.hmac256(data, key);
}

export function aesEncrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  return MobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex);
}

export function aesDecrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  return MobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex);
}

export function aesEncryptFile(
  filePath: string,
  base64UrlKey: string,
  base64Iv: string
): Promise<string> {
  return MobileCrypto.aesEncryptFile(filePath, base64UrlKey, base64Iv);
}

export function aesDecryptFile(
  filePath: string,
  base64UrlKey: string,
  base64Iv: string
): Promise<string> {
  return MobileCrypto.aesDecryptFile(filePath, base64UrlKey, base64Iv);
}

export function randomUuid(): Promise<string> {
  return MobileCrypto.randomUuid();
}

export function randomKey(length: number): Promise<string> {
  return MobileCrypto.randomKey(length);
}

export function randomBytes(size: number): Promise<string> {
  return MobileCrypto.randomBytes(size);
}

// RSA Functions
export function rsaGenerateKeys(
  keySize?: number
): Promise<{ public: string; private: string }> {
  return MobileCrypto.rsaGenerateKeys(keySize);
}

export function rsaEncrypt(
  message: string,
  publicKey: string
): Promise<string> {
  return MobileCrypto.rsaEncrypt(message, publicKey);
}

export function rsaEncrypt64(
  message: string,
  publicKey: string
): Promise<string> {
  return MobileCrypto.rsaEncrypt64(message, publicKey);
}

export function rsaDecrypt(
  encodedMessage: string,
  privateKey: string
): Promise<string> {
  return MobileCrypto.rsaDecrypt(encodedMessage, privateKey);
}

export function rsaDecrypt64(
  encodedMessage: string,
  privateKey: string
): Promise<string> {
  return MobileCrypto.rsaDecrypt64(encodedMessage, privateKey);
}

export function rsaSign(
  message: string,
  privateKey: string,
  hash?: string
): Promise<string> {
  return MobileCrypto.rsaSign(message, privateKey, hash);
}

export function rsaSign64(
  message: string,
  privateKey: string,
  hash?: string
): Promise<string> {
  return MobileCrypto.rsaSign64(message, privateKey, hash);
}

export function rsaVerify(
  signature: string,
  message: string,
  publicKey: string,
  hash?: string
): Promise<boolean> {
  return MobileCrypto.rsaVerify(signature, message, publicKey, hash);
}

export function rsaVerify64(
  signature: string,
  message: string,
  publicKey: string,
  hash?: string
): Promise<boolean> {
  return MobileCrypto.rsaVerify64(signature, message, publicKey, hash);
}

export function rsaImportKey(jwk: JWK): Promise<string> {
  return MobileCrypto.rsaImportKey(jwk);
}

export function rsaExportKey(pem: string): Promise<JWK> {
  return MobileCrypto.rsaExportKey(pem);
}

// Utility Functions
export function calculateFileChecksum(filePath: string): Promise<string> {
  return MobileCrypto.calculateFileChecksum(filePath);
}

export function getRandomValues(length: number): Promise<string> {
  return MobileCrypto.getRandomValues(length);
}
