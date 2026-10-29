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
const runBySize = (inputs, runSync, runAsync) => rejectOnThrow(() => inputs.reduce((total, input) => total + inputSize(input), 0) <= SYNC_INPUT_LIMIT ? runSync() : runAsync());
const rejectingPrivateKey = key => ({
  decrypt: ciphertext => rejectOnThrow(() => key.decrypt(ciphertext)),
  sign: (message, hash) => rejectOnThrow(() => key.sign(message, hash)),
  exportJwk: () => key.exportJwk()
});
const rejectingPublicKey = key => ({
  encrypt: plaintext => rejectOnThrow(() => key.encrypt(plaintext)),
  verify: (signature, message, hash) => rejectOnThrow(() => key.verify(signature, message, hash)),
  exportJwk: () => key.exportJwk()
});
const rejectingKeyPair = ({
  publicKey,
  privateKey
}) => ({
  publicKey: rejectingPublicKey(publicKey),
  privateKey: rejectingPrivateKey(privateKey)
});
export function sha(data, algorithm) {
  return runBySize([data], () => MobileCrypto.shaSync(data, algorithm), () => MobileCrypto.sha(data, algorithm));
}
export function hmac256(data, key) {
  return runBySize([data, key], () => MobileCrypto.hmac256Sync(data, key), () => MobileCrypto.hmac256(data, key));
}
export function aesGenerateKey(byteLength) {
  return MobileCrypto.aesGenerateKey(byteLength);
}
export function aesImportKey(base64Url) {
  return MobileCrypto.aesImportKey(base64Url);
}
export function aesDeriveKey(passwordBase64, saltBase64, iterations, byteLength, hash) {
  return rejectOnThrow(() => MobileCrypto.aesDeriveKey(passwordBase64, saltBase64, iterations, byteLength, hash));
}
export function aesGcmEncrypt(key, plaintext) {
  return runBySize([plaintext], () => MobileCrypto.aesGcmEncryptSync(key, plaintext), () => MobileCrypto.aesGcmEncrypt(key, plaintext));
}
export function aesGcmDecrypt(key, ciphertext, iv) {
  return runBySize([ciphertext], () => MobileCrypto.aesGcmDecryptSync(key, ciphertext, iv), () => MobileCrypto.aesGcmDecrypt(key, ciphertext, iv));
}
export function aesCbcEncrypt(key, plaintext) {
  return runBySize([plaintext], () => MobileCrypto.aesCbcEncryptSync(key, plaintext), () => MobileCrypto.aesCbcEncrypt(key, plaintext));
}
export function aesCbcDecrypt(key, ivAndCiphertext) {
  return runBySize([ivAndCiphertext], () => MobileCrypto.aesCbcDecryptSync(key, ivAndCiphertext), () => MobileCrypto.aesCbcDecrypt(key, ivAndCiphertext));
}
export function aesEncryptFile(filePath) {
  return rejectOnThrow(() => MobileCrypto.aesEncryptFile(filePath));
}
export function aesDecryptFile(filePath, key, iv, sha256) {
  return rejectOnThrow(() => MobileCrypto.aesDecryptFile(filePath, key, iv, sha256));
}
export function rsaGenerateKeys(keySize) {
  return rejectOnThrow(() => MobileCrypto.rsaGenerateKeys(keySize)).then(rejectingKeyPair);
}
export function rsaImportPrivateKey(jwk) {
  return rejectOnThrow(() => MobileCrypto.rsaImportPrivateKey(jwk)).then(rejectingPrivateKey);
}
export function rsaImportPublicKey(jwk) {
  return rejectOnThrow(() => MobileCrypto.rsaImportPublicKey(jwk)).then(rejectingPublicKey);
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