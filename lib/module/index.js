"use strict";

import MobileCrypto from "./NativeMobileCrypto.js";

// Export the JWK type for users

export function shaBase64(data, algorithm) {
  return MobileCrypto.shaBase64(data, algorithm);
}
export function shaUtf8(data, algorithm) {
  return MobileCrypto.shaUtf8(data, algorithm);
}
export function pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash) {
  return MobileCrypto.pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash);
}
export function hmac256(data, key) {
  return MobileCrypto.hmac256(data, key);
}
export function aesEncrypt(dataBase64, keyHex, ivHex) {
  return MobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex);
}
export function aesDecrypt(dataBase64, keyHex, ivHex) {
  return MobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex);
}
export function aesEncryptFile(filePath, base64UrlKey, base64Iv) {
  return MobileCrypto.aesEncryptFile(filePath, base64UrlKey, base64Iv);
}
export function aesDecryptFile(filePath, base64UrlKey, base64Iv) {
  return MobileCrypto.aesDecryptFile(filePath, base64UrlKey, base64Iv);
}
export function randomUuid() {
  return MobileCrypto.randomUuid();
}
export function randomKey(length) {
  return MobileCrypto.randomKey(length);
}
export function randomBytes(size) {
  return MobileCrypto.randomBytes(size);
}

// RSA Functions
export function rsaGenerateKeys(keySize) {
  return MobileCrypto.rsaGenerateKeys(keySize);
}
export function rsaEncrypt(message, publicKey) {
  return MobileCrypto.rsaEncrypt(message, publicKey);
}
export function rsaEncrypt64(message, publicKey) {
  return MobileCrypto.rsaEncrypt64(message, publicKey);
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
  return MobileCrypto.rsaVerify(signature, message, publicKey, hash);
}
export function rsaVerify64(signature, message, publicKey, hash) {
  return MobileCrypto.rsaVerify64(signature, message, publicKey, hash);
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
  return MobileCrypto.getRandomValues(length);
}
//# sourceMappingURL=index.js.map