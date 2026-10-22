import { NitroModules } from 'react-native-nitro-modules';
import type { JWK } from './specs/JWK';
import type { MobileCrypto as MobileCryptoSpec } from './specs/MobileCrypto.nitro';

const MobileCrypto =
  NitroModules.createHybridObject<MobileCryptoSpec>('MobileCrypto');

const nullWhenUndefined = (value: string | undefined) =>
  (value ?? null) as string;

const SYNC_INPUT_LIMIT = 32 * 1024;

const isSmall = (...inputs: string[]) =>
  inputs.reduce((total, input) => total + input.length, 0) <= SYNC_INPUT_LIMIT;

const resolveSync = <T,>(operation: () => T): Promise<T> => {
  try {
    return Promise.resolve(operation());
  } catch (error) {
    return Promise.reject(error);
  }
};

// Export the JWK type for users
export type { JWK };

export function shaBase64(data: string, algorithm: string): Promise<string> {
  return isSmall(data)
    ? resolveSync(() => MobileCrypto.shaBase64Sync(data, algorithm))
    : MobileCrypto.shaBase64(data, algorithm);
}

export function shaUtf8(data: string, algorithm: string): Promise<string> {
  return isSmall(data)
    ? resolveSync(() => MobileCrypto.shaUtf8Sync(data, algorithm))
    : MobileCrypto.shaUtf8(data, algorithm);
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
  return isSmall(data, key)
    ? resolveSync(() => MobileCrypto.hmac256Sync(data, key))
    : MobileCrypto.hmac256(data, key);
}

export function aesEncrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const ciphertext = isSmall(dataBase64)
    ? resolveSync(() => MobileCrypto.aesEncryptSync(dataBase64, keyHex, ivHex))
    : MobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex);
  return ciphertext.then(nullWhenUndefined);
}

export function aesDecrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const plaintext = isSmall(dataBase64)
    ? resolveSync(() => MobileCrypto.aesDecryptSync(dataBase64, keyHex, ivHex))
    : MobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex);
  return plaintext.then(nullWhenUndefined);
}

export function aesGcmEncrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const ciphertext = isSmall(dataBase64)
    ? resolveSync(() =>
        MobileCrypto.aesGcmEncryptSync(dataBase64, keyHex, ivHex)
      )
    : MobileCrypto.aesGcmEncrypt(dataBase64, keyHex, ivHex);
  return ciphertext.then(nullWhenUndefined);
}

export function aesGcmDecrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const plaintext = isSmall(dataBase64)
    ? resolveSync(() =>
        MobileCrypto.aesGcmDecryptSync(dataBase64, keyHex, ivHex)
      )
    : MobileCrypto.aesGcmDecrypt(dataBase64, keyHex, ivHex);
  return plaintext.then(nullWhenUndefined);
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
  return resolveSync(() => MobileCrypto.randomUuid());
}

export function randomKey(length: number): Promise<string> {
  return resolveSync(() => MobileCrypto.randomKey(length));
}

export function randomBytes(size: number): Promise<string> {
  return resolveSync(() => MobileCrypto.randomBytes(size));
}

// RSA Functions
export function rsaGenerateKeys(
  keySize?: number
): Promise<{ public: string; private: string }> {
  return MobileCrypto.rsaGenerateKeys(keySize).then(
    ({ publicKey, privateKey }) => ({ public: publicKey, private: privateKey })
  );
}

export function rsaEncrypt(
  message: string,
  publicKey: string
): Promise<string> {
  return resolveSync(() => MobileCrypto.rsaEncrypt(message, publicKey));
}

export function rsaEncrypt64(
  message: string,
  publicKey: string
): Promise<string> {
  return resolveSync(() => MobileCrypto.rsaEncrypt64(message, publicKey));
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
  return isSmall(message)
    ? resolveSync(() =>
        MobileCrypto.rsaVerifySync(signature, message, publicKey, hash)
      )
    : MobileCrypto.rsaVerify(signature, message, publicKey, hash);
}

export function rsaVerify64(
  signature: string,
  message: string,
  publicKey: string,
  hash?: string
): Promise<boolean> {
  return isSmall(message)
    ? resolveSync(() =>
        MobileCrypto.rsaVerify64Sync(signature, message, publicKey, hash)
      )
    : MobileCrypto.rsaVerify64(signature, message, publicKey, hash);
}

export function rsaImportKey(jwk: JWK): Promise<string> {
  return MobileCrypto.rsaImportKey(jwk);
}

export function rsaExportKey(pem: string): Promise<JWK> {
  return MobileCrypto.rsaExportKey(pem);
}

export function rsaPemToJwk(pemKey: string): Promise<JWK> {
  return MobileCrypto.rsaExportKey(pemKey);
}

// Utility Functions
export function calculateFileChecksum(filePath: string): Promise<string> {
  return MobileCrypto.calculateFileChecksum(filePath);
}

export function getRandomValues(length: number): Promise<string> {
  return resolveSync(() => MobileCrypto.getRandomValues(length));
}
