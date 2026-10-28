"use strict";

import { NitroModules } from 'react-native-nitro-modules';
const MobileCrypto = NitroModules.createHybridObject('MobileCrypto');
const nullWhenUndefined = value => value ?? null;
const SYNC_INPUT_LIMIT = 32 * 1024;
const inputSize = input => typeof input === 'string' ? input.length : input.byteLength;
const rejectOnThrow = operation => {
  try {
    return Promise.resolve(operation());
  } catch (error) {
    return Promise.reject(error);
  }
};
const runBySize = (inputs, runSync, runAsync) => rejectOnThrow(() => inputs.reduce((total, input) => total + inputSize(input), 0) <= SYNC_INPUT_LIMIT ? runSync() : runAsync());
export function shaBase64(data, algorithm) {
  return runBySize([data], () => MobileCrypto.shaBase64Sync(data, algorithm), () => MobileCrypto.shaBase64(data, algorithm));
}
export function shaUtf8(data, algorithm) {
  return runBySize([data], () => MobileCrypto.shaUtf8Sync(data, algorithm), () => MobileCrypto.shaUtf8(data, algorithm));
}
export function pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash) {
  return rejectOnThrow(() => MobileCrypto.pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash));
}
export function hmac256(data, key) {
  return runBySize([data, key], () => MobileCrypto.hmac256Sync(data, key), () => MobileCrypto.hmac256(data, key));
}
export function aesEncrypt(dataBase64, keyHex, ivHex) {
  const ciphertext = runBySize([dataBase64], () => MobileCrypto.aesEncryptSync(dataBase64, keyHex, ivHex), () => MobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex));
  return ciphertext.then(nullWhenUndefined);
}
export function aesDecrypt(dataBase64, keyHex, ivHex) {
  const plaintext = runBySize([dataBase64], () => MobileCrypto.aesDecryptSync(dataBase64, keyHex, ivHex), () => MobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex));
  return plaintext.then(nullWhenUndefined);
}
export function aesGcmEncrypt(dataBase64, keyHex, ivHex) {
  const ciphertext = runBySize([dataBase64], () => MobileCrypto.aesGcmEncryptSync(dataBase64, keyHex, ivHex), () => MobileCrypto.aesGcmEncrypt(dataBase64, keyHex, ivHex));
  return ciphertext.then(nullWhenUndefined);
}
export function aesGcmDecrypt(dataBase64, keyHex, ivHex) {
  const plaintext = runBySize([dataBase64], () => MobileCrypto.aesGcmDecryptSync(dataBase64, keyHex, ivHex), () => MobileCrypto.aesGcmDecrypt(dataBase64, keyHex, ivHex));
  return plaintext.then(nullWhenUndefined);
}
export function aesEncryptFile(filePath, base64UrlKey, base64Iv) {
  return rejectOnThrow(() => MobileCrypto.aesEncryptFile(filePath, base64UrlKey, base64Iv));
}
export function aesDecryptFile(filePath, base64UrlKey, base64Iv) {
  return rejectOnThrow(() => MobileCrypto.aesDecryptFile(filePath, base64UrlKey, base64Iv));
}
export function randomUuid() {
  return rejectOnThrow(() => MobileCrypto.randomUuid());
}
export function randomKey(length) {
  return rejectOnThrow(() => MobileCrypto.randomKey(length));
}
export function randomBytes(size) {
  return rejectOnThrow(() => MobileCrypto.randomBytes(size));
}

// RSA Functions
export function rsaGenerateKeys(keySize) {
  return rejectOnThrow(() => MobileCrypto.rsaGenerateKeys(keySize)).then(({
    publicKey,
    privateKey
  }) => ({
    public: publicKey,
    private: privateKey
  }));
}
export function rsaEncrypt(message, publicKey) {
  return rejectOnThrow(() => MobileCrypto.rsaEncrypt(message, publicKey));
}
export function rsaEncrypt64(message, publicKey) {
  return rejectOnThrow(() => MobileCrypto.rsaEncrypt64(message, publicKey));
}
export function rsaDecrypt(encodedMessage, privateKey) {
  return rejectOnThrow(() => MobileCrypto.rsaDecrypt(encodedMessage, privateKey));
}
export function rsaDecrypt64(encodedMessage, privateKey) {
  return rejectOnThrow(() => MobileCrypto.rsaDecrypt64(encodedMessage, privateKey));
}
export function rsaSign(message, privateKey, hash) {
  return rejectOnThrow(() => MobileCrypto.rsaSign(message, privateKey, hash));
}
export function rsaSign64(message, privateKey, hash) {
  return rejectOnThrow(() => MobileCrypto.rsaSign64(message, privateKey, hash));
}
export function rsaVerify(signature, message, publicKey, hash) {
  return runBySize([message], () => MobileCrypto.rsaVerifySync(signature, message, publicKey, hash), () => MobileCrypto.rsaVerify(signature, message, publicKey, hash));
}
export function rsaVerify64(signature, message, publicKey, hash) {
  return runBySize([message], () => MobileCrypto.rsaVerify64Sync(signature, message, publicKey, hash), () => MobileCrypto.rsaVerify64(signature, message, publicKey, hash));
}
export function rsaImportKey(jwk) {
  return rejectOnThrow(() => MobileCrypto.rsaImportKey(jwk));
}
const withoutUndefinedFields = jwk => Object.fromEntries(Object.entries(jwk).filter(([, value]) => value !== undefined));
export function rsaExportKey(pem) {
  return rejectOnThrow(() => MobileCrypto.rsaExportKey(pem)).then(withoutUndefinedFields);
}
export function rsaPemToJwk(pemKey) {
  return rsaExportKey(pemKey);
}

// Utility Functions
export function calculateFileChecksum(filePath) {
  return rejectOnThrow(() => MobileCrypto.calculateFileChecksum(filePath));
}
export function getRandomValues(length) {
  return rejectOnThrow(() => MobileCrypto.getRandomValues(length));
}
export function rsaImportPrivateKey(pem) {
  return rejectOnThrow(() => MobileCrypto.rsaImportPrivateKey(pem));
}
export function rsaImportPublicKey(pem) {
  return rejectOnThrow(() => MobileCrypto.rsaImportPublicKey(pem));
}
export function shaBuffer(data, algorithm) {
  return runBySize([data], () => MobileCrypto.shaBufferSync(data, algorithm), () => MobileCrypto.shaBuffer(data, algorithm));
}
export function hmac256Buffer(data, key) {
  return runBySize([data, key], () => MobileCrypto.hmac256BufferSync(data, key), () => MobileCrypto.hmac256Buffer(data, key));
}
export function aesEncryptBuffer(data, key, iv) {
  return runBySize([data], () => MobileCrypto.aesEncryptBufferSync(data, key, iv), () => MobileCrypto.aesEncryptBuffer(data, key, iv));
}
export function aesDecryptBuffer(data, key, iv) {
  return runBySize([data], () => MobileCrypto.aesDecryptBufferSync(data, key, iv), () => MobileCrypto.aesDecryptBuffer(data, key, iv));
}
export function aesGcmEncryptBuffer(data, key, iv) {
  return runBySize([data], () => MobileCrypto.aesGcmEncryptBufferSync(data, key, iv), () => MobileCrypto.aesGcmEncryptBuffer(data, key, iv));
}
export function aesGcmDecryptBuffer(data, key, iv) {
  return runBySize([data], () => MobileCrypto.aesGcmDecryptBufferSync(data, key, iv), () => MobileCrypto.aesGcmDecryptBuffer(data, key, iv));
}
export function randomBytesBuffer(size) {
  return rejectOnThrow(() => MobileCrypto.randomBytesBuffer(size));
}
//# sourceMappingURL=index.js.map