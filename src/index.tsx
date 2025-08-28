import MobileCrypto from './NativeMobileCrypto';

export function multiply(a: number, b: number): number {
  return MobileCrypto.multiply(a, b);
}

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
