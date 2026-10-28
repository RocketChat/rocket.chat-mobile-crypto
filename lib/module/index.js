"use strict";

import { NitroModules } from 'react-native-nitro-modules';
const MobileCrypto = NitroModules.createHybridObject('MobileCrypto');
const nullWhenUndefined = value => value ?? null;
const SYNC_INPUT_LIMIT = 32 * 1024;
const isSmall = (...inputs) => inputs.reduce((total, input) => total + input.length, 0) <= SYNC_INPUT_LIMIT;
const isSmallBuffer = (...inputs) => inputs.reduce((total, input) => total + input.byteLength, 0) <= SYNC_INPUT_LIMIT;
const resolveSync = operation => {
  try {
    return Promise.resolve(operation());
  } catch (error) {
    return Promise.reject(error);
  }
};
export function shaBase64(data, algorithm) {
  return isSmall(data) ? resolveSync(() => MobileCrypto.shaBase64Sync(data, algorithm)) : MobileCrypto.shaBase64(data, algorithm);
}
export function shaUtf8(data, algorithm) {
  return isSmall(data) ? resolveSync(() => MobileCrypto.shaUtf8Sync(data, algorithm)) : MobileCrypto.shaUtf8(data, algorithm);
}
export function pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash) {
  return MobileCrypto.pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash);
}
export function hmac256(data, key) {
  return isSmall(data, key) ? resolveSync(() => MobileCrypto.hmac256Sync(data, key)) : MobileCrypto.hmac256(data, key);
}
export function aesEncrypt(dataBase64, keyHex, ivHex) {
  const ciphertext = isSmall(dataBase64) ? resolveSync(() => MobileCrypto.aesEncryptSync(dataBase64, keyHex, ivHex)) : MobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex);
  return ciphertext.then(nullWhenUndefined);
}
export function aesDecrypt(dataBase64, keyHex, ivHex) {
  const plaintext = isSmall(dataBase64) ? resolveSync(() => MobileCrypto.aesDecryptSync(dataBase64, keyHex, ivHex)) : MobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex);
  return plaintext.then(nullWhenUndefined);
}
export function aesGcmEncrypt(dataBase64, keyHex, ivHex) {
  const ciphertext = isSmall(dataBase64) ? resolveSync(() => MobileCrypto.aesGcmEncryptSync(dataBase64, keyHex, ivHex)) : MobileCrypto.aesGcmEncrypt(dataBase64, keyHex, ivHex);
  return ciphertext.then(nullWhenUndefined);
}
export function aesGcmDecrypt(dataBase64, keyHex, ivHex) {
  const plaintext = isSmall(dataBase64) ? resolveSync(() => MobileCrypto.aesGcmDecryptSync(dataBase64, keyHex, ivHex)) : MobileCrypto.aesGcmDecrypt(dataBase64, keyHex, ivHex);
  return plaintext.then(nullWhenUndefined);
}
export function aesEncryptFile(filePath, base64UrlKey, base64Iv) {
  return MobileCrypto.aesEncryptFile(filePath, base64UrlKey, base64Iv);
}
export function aesDecryptFile(filePath, base64UrlKey, base64Iv) {
  return MobileCrypto.aesDecryptFile(filePath, base64UrlKey, base64Iv);
}
export function randomUuid() {
  return resolveSync(() => MobileCrypto.randomUuid());
}
export function randomKey(length) {
  return resolveSync(() => MobileCrypto.randomKey(length));
}
export function randomBytes(size) {
  return resolveSync(() => MobileCrypto.randomBytes(size));
}

// RSA Functions
export function rsaGenerateKeys(keySize) {
  return MobileCrypto.rsaGenerateKeys(keySize).then(({
    publicKey,
    privateKey
  }) => ({
    public: publicKey,
    private: privateKey
  }));
}
export function rsaEncrypt(message, publicKey) {
  return resolveSync(() => MobileCrypto.rsaEncrypt(message, publicKey));
}
export function rsaEncrypt64(message, publicKey) {
  return resolveSync(() => MobileCrypto.rsaEncrypt64(message, publicKey));
}
export function rsaDecrypt(encodedMessage, privateKey) {
  return MobileCrypto.rsaDecrypt(encodedMessage, privateKey);
}
export function rsaDecrypt64(encodedMessage, privateKey) {
  return MobileCrypto.rsaDecrypt64(encodedMessage, privateKey);
}
export function rsaSign(message, privateKey, hash) {
  return MobileCrypto.rsaSign(message, privateKey, hash);
}
export function rsaSign64(message, privateKey, hash) {
  return MobileCrypto.rsaSign64(message, privateKey, hash);
}
export function rsaVerify(signature, message, publicKey, hash) {
  return isSmall(message) ? resolveSync(() => MobileCrypto.rsaVerifySync(signature, message, publicKey, hash)) : MobileCrypto.rsaVerify(signature, message, publicKey, hash);
}
export function rsaVerify64(signature, message, publicKey, hash) {
  return isSmall(message) ? resolveSync(() => MobileCrypto.rsaVerify64Sync(signature, message, publicKey, hash)) : MobileCrypto.rsaVerify64(signature, message, publicKey, hash);
}
export function rsaImportKey(jwk) {
  return MobileCrypto.rsaImportKey(jwk);
}
export function rsaExportKey(pem) {
  return MobileCrypto.rsaExportKey(pem);
}
export function rsaPemToJwk(pemKey) {
  return MobileCrypto.rsaExportKey(pemKey);
}

// Utility Functions
export function calculateFileChecksum(filePath) {
  return MobileCrypto.calculateFileChecksum(filePath);
}
export function getRandomValues(length) {
  return resolveSync(() => MobileCrypto.getRandomValues(length));
}
export function rsaImportPrivateKey(pem) {
  return MobileCrypto.rsaImportPrivateKey(pem);
}
export function rsaImportPublicKey(pem) {
  return MobileCrypto.rsaImportPublicKey(pem);
}

// ArrayBuffer Functions
export function shaBuffer(data, algorithm) {
  return isSmallBuffer(data) ? resolveSync(() => MobileCrypto.shaBufferSync(data, algorithm)) : MobileCrypto.shaBuffer(data, algorithm);
}
export function hmac256Buffer(data, key) {
  return isSmallBuffer(data, key) ? resolveSync(() => MobileCrypto.hmac256BufferSync(data, key)) : MobileCrypto.hmac256Buffer(data, key);
}
export function aesEncryptBuffer(data, key, iv) {
  return isSmallBuffer(data) ? resolveSync(() => MobileCrypto.aesEncryptBufferSync(data, key, iv)) : MobileCrypto.aesEncryptBuffer(data, key, iv);
}
export function aesDecryptBuffer(data, key, iv) {
  return isSmallBuffer(data) ? resolveSync(() => MobileCrypto.aesDecryptBufferSync(data, key, iv)) : MobileCrypto.aesDecryptBuffer(data, key, iv);
}
export function aesGcmEncryptBuffer(data, key, iv) {
  return isSmallBuffer(data) ? resolveSync(() => MobileCrypto.aesGcmEncryptBufferSync(data, key, iv)) : MobileCrypto.aesGcmEncryptBuffer(data, key, iv);
}
export function aesGcmDecryptBuffer(data, key, iv) {
  return isSmallBuffer(data) ? resolveSync(() => MobileCrypto.aesGcmDecryptBufferSync(data, key, iv)) : MobileCrypto.aesGcmDecryptBuffer(data, key, iv);
}
export function randomBytesBuffer(size) {
  return resolveSync(() => MobileCrypto.randomBytesBuffer(size));
}
//# sourceMappingURL=index.js.map