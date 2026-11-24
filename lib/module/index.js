"use strict";

import { NitroModules } from 'react-native-nitro-modules';
const MobileCrypto = NitroModules.createHybridObject('MobileCrypto');
const SYNC_INPUT_LIMIT = 32 * 1024;
const inputSize = input => typeof input === 'string' ? input.length : input.byteLength;
const rejectOnThrow = operation => {
  try {
    return Promise.resolve(operation());
  } catch (error) {
    return Promise.reject(error);
  }
};
const runBySize = (sizedInputs, runSync, runAsync) => rejectOnThrow(() => sizedInputs().reduce((total, input) => total + inputSize(input), 0) <= SYNC_INPUT_LIMIT ? runSync() : runAsync());
export function sha(data, algorithm) {
  return runBySize(() => [data], () => MobileCrypto.shaSync(data, algorithm), () => MobileCrypto.sha(data, algorithm));
}
export function hmac256(data, key) {
  return runBySize(() => [data, key], () => MobileCrypto.hmac256Sync(data, key), () => MobileCrypto.hmac256(data, key));
}
export function aesGenerateKey(byteLength) {
  return MobileCrypto.aesGenerateKey(byteLength);
}
export function aesImportKey(base64Url) {
  return MobileCrypto.aesImportKey(base64Url);
}
export function aesDeriveKey(passwordBase64, saltBase64, options) {
  return rejectOnThrow(() => MobileCrypto.aesDeriveKey(passwordBase64, saltBase64, options.iterations, options.byteLength, options.hash));
}
export function aesGcmEncrypt(key, plaintext) {
  return runBySize(() => [plaintext], () => MobileCrypto.aesGcmEncryptSync(key, plaintext), () => MobileCrypto.aesGcmEncrypt(key, plaintext));
}
export function aesGcmDecrypt(key, encrypted) {
  return runBySize(() => [encrypted.ciphertext], () => MobileCrypto.aesGcmDecryptSync(key, encrypted), () => MobileCrypto.aesGcmDecrypt(key, encrypted));
}
export function aesCbcEncrypt(key, plaintext) {
  return runBySize(() => [plaintext], () => MobileCrypto.aesCbcEncryptSync(key, plaintext), () => MobileCrypto.aesCbcEncrypt(key, plaintext));
}
export function aesCbcDecrypt(key, ivAndCiphertext) {
  return runBySize(() => [ivAndCiphertext], () => MobileCrypto.aesCbcDecryptSync(key, ivAndCiphertext), () => MobileCrypto.aesCbcDecrypt(key, ivAndCiphertext));
}
export function aesEncryptFile(filePath) {
  return rejectOnThrow(() => MobileCrypto.aesEncryptFile(filePath));
}
export function aesDecryptFile(file) {
  return rejectOnThrow(() => MobileCrypto.aesDecryptFile(file));
}
export function rsaGenerateKeys(keySize) {
  return rejectOnThrow(() => MobileCrypto.rsaGenerateKeys(keySize));
}
export function rsaImportPrivateKey(jwk) {
  return rejectOnThrow(() => MobileCrypto.rsaImportPrivateKey(jwk));
}
export function rsaImportPublicKey(jwk) {
  return rejectOnThrow(() => MobileCrypto.rsaImportPublicKey(jwk));
}
export function rsaEncrypt(publicKey, plaintext) {
  return rejectOnThrow(() => MobileCrypto.rsaEncrypt(publicKey, plaintext));
}
export function rsaDecrypt(privateKey, ciphertext) {
  return rejectOnThrow(() => MobileCrypto.rsaDecrypt(privateKey, ciphertext));
}
export function rsaSign(privateKey, message, hash) {
  return rejectOnThrow(() => MobileCrypto.rsaSign(privateKey, message, hash));
}
export function rsaVerify(publicKey, signature, message, hash) {
  return rejectOnThrow(() => MobileCrypto.rsaVerify(publicKey, signature, message, hash));
}
export function rsaVerifyJwt(publicKey, jwt) {
  return rejectOnThrow(() => MobileCrypto.rsaVerifyJwt(publicKey, jwt));
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
//# sourceMappingURL=index.js.map