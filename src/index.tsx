import { NitroModules } from 'react-native-nitro-modules';
import type { JWK } from './specs/JWK';
import type { MobileCrypto as MobileCryptoSpec } from './specs/MobileCrypto.nitro';
import type { PBKDF2HashAlgorithm } from './specs/PBKDF2HashAlgorithm';
import type { RSAHashAlgorithm } from './specs/RSAHashAlgorithm';
import type { RSAPrivateKey as HybridRSAPrivateKey } from './specs/RSAPrivateKey.nitro';
import type { RSAPublicKey as HybridRSAPublicKey } from './specs/RSAPublicKey.nitro';
import type { SHAAlgorithm } from './specs/SHAAlgorithm';

const MobileCrypto =
  NitroModules.createHybridObject<MobileCryptoSpec>('MobileCrypto');

const nullWhenUndefined = (value: string | undefined) =>
  (value ?? null) as string;

const SYNC_INPUT_LIMIT = 32 * 1024;

type SizedInput = string | ArrayBuffer;

const inputSize = (input: SizedInput) =>
  typeof input === 'string' ? input.length : input.byteLength;

const rejectOnThrow = <T,>(operation: () => T | Promise<T>): Promise<T> => {
  try {
    return Promise.resolve(operation());
  } catch (error) {
    return Promise.reject(error);
  }
};

const runBySize = <T,>(
  inputs: SizedInput[],
  runSync: () => T,
  runAsync: () => Promise<T>
): Promise<T> =>
  rejectOnThrow(() =>
    inputs.reduce((total, input) => total + inputSize(input), 0) <=
    SYNC_INPUT_LIMIT
      ? runSync()
      : runAsync()
  );

export interface RSAPrivateKey {
  decrypt(ciphertext: ArrayBuffer): Promise<ArrayBuffer>;
  sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
}

export interface RSAPublicKey {
  encrypt(plaintext: ArrayBuffer): Promise<ArrayBuffer>;
  verify(
    signature: ArrayBuffer,
    message: ArrayBuffer,
    hash: RSAHashAlgorithm
  ): Promise<boolean>;
}

const rejectingPrivateKey = (key: HybridRSAPrivateKey): RSAPrivateKey => ({
  decrypt: (ciphertext) => rejectOnThrow(() => key.decrypt(ciphertext)),
  sign: (message, hash) => rejectOnThrow(() => key.sign(message, hash)),
});

const rejectingPublicKey = (key: HybridRSAPublicKey): RSAPublicKey => ({
  encrypt: (plaintext) => rejectOnThrow(() => key.encrypt(plaintext)),
  verify: (signature, message, hash) =>
    rejectOnThrow(() => key.verify(signature, message, hash)),
});

export type { JWK, PBKDF2HashAlgorithm, RSAHashAlgorithm, SHAAlgorithm };

export function shaBase64(
  data: string,
  algorithm: SHAAlgorithm
): Promise<string> {
  return runBySize(
    [data],
    () => MobileCrypto.shaBase64Sync(data, algorithm),
    () => MobileCrypto.shaBase64(data, algorithm)
  );
}

export function shaUtf8(
  data: string,
  algorithm: SHAAlgorithm
): Promise<string> {
  return runBySize(
    [data],
    () => MobileCrypto.shaUtf8Sync(data, algorithm),
    () => MobileCrypto.shaUtf8(data, algorithm)
  );
}

export function pbkdf2Hash(
  pwdBase64: string,
  saltBase64: string,
  iterations: number,
  keyLen: number,
  hash: PBKDF2HashAlgorithm
): Promise<string> {
  return rejectOnThrow(() =>
    MobileCrypto.pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash)
  );
}

export function hmac256(data: string, key: string): Promise<string> {
  return runBySize(
    [data, key],
    () => MobileCrypto.hmac256Sync(data, key),
    () => MobileCrypto.hmac256(data, key)
  );
}

export function aesEncrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const ciphertext = runBySize(
    [dataBase64],
    () => MobileCrypto.aesEncryptSync(dataBase64, keyHex, ivHex),
    () => MobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex)
  );
  return ciphertext.then(nullWhenUndefined);
}

export function aesDecrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const plaintext = runBySize(
    [dataBase64],
    () => MobileCrypto.aesDecryptSync(dataBase64, keyHex, ivHex),
    () => MobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex)
  );
  return plaintext.then(nullWhenUndefined);
}

export function aesGcmEncrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const ciphertext = runBySize(
    [dataBase64],
    () => MobileCrypto.aesGcmEncryptSync(dataBase64, keyHex, ivHex),
    () => MobileCrypto.aesGcmEncrypt(dataBase64, keyHex, ivHex)
  );
  return ciphertext.then(nullWhenUndefined);
}

export function aesGcmDecrypt(
  dataBase64: string,
  keyHex: string,
  ivHex: string
): Promise<string> {
  const plaintext = runBySize(
    [dataBase64],
    () => MobileCrypto.aesGcmDecryptSync(dataBase64, keyHex, ivHex),
    () => MobileCrypto.aesGcmDecrypt(dataBase64, keyHex, ivHex)
  );
  return plaintext.then(nullWhenUndefined);
}

export function aesEncryptFile(
  filePath: string,
  base64UrlKey: string,
  base64Iv: string
): Promise<string> {
  return rejectOnThrow(() =>
    MobileCrypto.aesEncryptFile(filePath, base64UrlKey, base64Iv)
  );
}

export function aesDecryptFile(
  filePath: string,
  base64UrlKey: string,
  base64Iv: string
): Promise<string> {
  return rejectOnThrow(() =>
    MobileCrypto.aesDecryptFile(filePath, base64UrlKey, base64Iv)
  );
}

export function randomUuid(): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.randomUuid());
}

export function randomKey(length: number): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.randomKey(length));
}

export function randomBytes(size: number): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.randomBytes(size));
}

// RSA Functions
export function rsaGenerateKeys(
  keySize?: number
): Promise<{ public: string; private: string }> {
  return rejectOnThrow(() => MobileCrypto.rsaGenerateKeys(keySize)).then(
    ({ publicKey, privateKey }) => ({ public: publicKey, private: privateKey })
  );
}

export function rsaEncrypt(
  message: string,
  publicKey: string
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaEncrypt(message, publicKey));
}

export function rsaEncrypt64(
  message: string,
  publicKey: string
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaEncrypt64(message, publicKey));
}

export function rsaDecrypt(
  encodedMessage: string,
  privateKey: string
): Promise<string> {
  return rejectOnThrow(() =>
    MobileCrypto.rsaDecrypt(encodedMessage, privateKey)
  );
}

export function rsaDecrypt64(
  encodedMessage: string,
  privateKey: string
): Promise<string> {
  return rejectOnThrow(() =>
    MobileCrypto.rsaDecrypt64(encodedMessage, privateKey)
  );
}

export function rsaSign(
  message: string,
  privateKey: string,
  hash?: RSAHashAlgorithm
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaSign(message, privateKey, hash));
}

export function rsaSign64(
  message: string,
  privateKey: string,
  hash?: RSAHashAlgorithm
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaSign64(message, privateKey, hash));
}

export function rsaVerify(
  signature: string,
  message: string,
  publicKey: string,
  hash?: RSAHashAlgorithm
): Promise<boolean> {
  return runBySize(
    [message],
    () => MobileCrypto.rsaVerifySync(signature, message, publicKey, hash),
    () => MobileCrypto.rsaVerify(signature, message, publicKey, hash)
  );
}

export function rsaVerify64(
  signature: string,
  message: string,
  publicKey: string,
  hash?: RSAHashAlgorithm
): Promise<boolean> {
  return runBySize(
    [message],
    () => MobileCrypto.rsaVerify64Sync(signature, message, publicKey, hash),
    () => MobileCrypto.rsaVerify64(signature, message, publicKey, hash)
  );
}

export function rsaImportKey(jwk: JWK): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaImportKey(jwk));
}

const withoutUndefinedFields = (jwk: JWK): JWK =>
  Object.fromEntries(
    Object.entries(jwk).filter(([, value]) => value !== undefined)
  ) as JWK;

export function rsaExportKey(pem: string): Promise<JWK> {
  return rejectOnThrow(() => MobileCrypto.rsaExportKey(pem)).then(
    withoutUndefinedFields
  );
}

export function rsaPemToJwk(pemKey: string): Promise<JWK> {
  return rsaExportKey(pemKey);
}

// Utility Functions
export function calculateFileChecksum(filePath: string): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.calculateFileChecksum(filePath));
}

export function getRandomValues(length: number): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.getRandomValues(length));
}

export function rsaImportPrivateKey(pem: string): Promise<RSAPrivateKey> {
  return rejectOnThrow(() => MobileCrypto.rsaImportPrivateKey(pem)).then(
    rejectingPrivateKey
  );
}

export function rsaImportPublicKey(pem: string): Promise<RSAPublicKey> {
  return rejectOnThrow(() => MobileCrypto.rsaImportPublicKey(pem)).then(
    rejectingPublicKey
  );
}

export function shaBuffer(
  data: ArrayBuffer,
  algorithm: SHAAlgorithm
): Promise<ArrayBuffer> {
  return runBySize(
    [data],
    () => MobileCrypto.shaBufferSync(data, algorithm),
    () => MobileCrypto.shaBuffer(data, algorithm)
  );
}

export function hmac256Buffer(
  data: ArrayBuffer,
  key: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    [data, key],
    () => MobileCrypto.hmac256BufferSync(data, key),
    () => MobileCrypto.hmac256Buffer(data, key)
  );
}

export function aesEncryptBuffer(
  data: ArrayBuffer,
  key: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    [data],
    () => MobileCrypto.aesEncryptBufferSync(data, key, iv),
    () => MobileCrypto.aesEncryptBuffer(data, key, iv)
  );
}

export function aesDecryptBuffer(
  data: ArrayBuffer,
  key: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    [data],
    () => MobileCrypto.aesDecryptBufferSync(data, key, iv),
    () => MobileCrypto.aesDecryptBuffer(data, key, iv)
  );
}

export function aesGcmEncryptBuffer(
  data: ArrayBuffer,
  key: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    [data],
    () => MobileCrypto.aesGcmEncryptBufferSync(data, key, iv),
    () => MobileCrypto.aesGcmEncryptBuffer(data, key, iv)
  );
}

export function aesGcmDecryptBuffer(
  data: ArrayBuffer,
  key: ArrayBuffer,
  iv: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    [data],
    () => MobileCrypto.aesGcmDecryptBufferSync(data, key, iv),
    () => MobileCrypto.aesGcmDecryptBuffer(data, key, iv)
  );
}

export function randomBytesBuffer(size: number): Promise<ArrayBuffer> {
  return rejectOnThrow(() => MobileCrypto.randomBytesBuffer(size));
}
