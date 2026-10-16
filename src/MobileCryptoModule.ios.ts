import { NitroModules } from 'react-native-nitro-modules';
import type { Spec } from './NativeMobileCrypto';
import type { MobileCrypto } from './specs/MobileCrypto.nitro';

const mobileCrypto =
  NitroModules.createHybridObject<MobileCrypto>('MobileCrypto');

const nullWhenUndefined = (value: string | undefined) =>
  (value ?? null) as string;

const MobileCryptoModule: Spec = {
  shaBase64: (data, algorithm) => mobileCrypto.shaBase64(data, algorithm),
  shaUtf8: (data, algorithm) => mobileCrypto.shaUtf8(data, algorithm),
  pbkdf2Hash: (pwdBase64, saltBase64, iterations, keyLen, hash) =>
    mobileCrypto.pbkdf2Hash(pwdBase64, saltBase64, iterations, keyLen, hash),
  hmac256: (data, key) => mobileCrypto.hmac256(data, key),
  aesEncrypt: (dataBase64, keyHex, ivHex) =>
    mobileCrypto.aesEncrypt(dataBase64, keyHex, ivHex).then(nullWhenUndefined),
  aesDecrypt: (dataBase64, keyHex, ivHex) =>
    mobileCrypto.aesDecrypt(dataBase64, keyHex, ivHex).then(nullWhenUndefined),
  aesGcmEncrypt: (dataBase64, keyHex, ivHex) =>
    mobileCrypto
      .aesGcmEncrypt(dataBase64, keyHex, ivHex)
      .then(nullWhenUndefined),
  aesGcmDecrypt: (dataBase64, keyHex, ivHex) =>
    mobileCrypto
      .aesGcmDecrypt(dataBase64, keyHex, ivHex)
      .then(nullWhenUndefined),
  aesEncryptFile: (filePath, base64UrlKey, base64Iv) =>
    mobileCrypto.aesEncryptFile(filePath, base64UrlKey, base64Iv),
  aesDecryptFile: (filePath, base64UrlKey, base64Iv) =>
    mobileCrypto.aesDecryptFile(filePath, base64UrlKey, base64Iv),
  randomUuid: () => mobileCrypto.randomUuid(),
  randomKey: (length) => mobileCrypto.randomKey(length),
  randomBytes: (size) => mobileCrypto.randomBytes(size),
  rsaGenerateKeys: (keySize) =>
    mobileCrypto.rsaGenerateKeys(keySize).then(({ publicKey, privateKey }) => ({
      public: publicKey,
      private: privateKey,
    })),
  rsaEncrypt: (message, publicKey) =>
    mobileCrypto.rsaEncrypt(message, publicKey),
  rsaEncrypt64: (message, publicKey) =>
    mobileCrypto.rsaEncrypt64(message, publicKey),
  rsaDecrypt: (encodedMessage, privateKey) =>
    mobileCrypto.rsaDecrypt(encodedMessage, privateKey),
  rsaDecrypt64: (encodedMessage, privateKey) =>
    mobileCrypto.rsaDecrypt64(encodedMessage, privateKey),
  rsaSign: (message, privateKey, hash) =>
    mobileCrypto.rsaSign(message, privateKey, hash),
  rsaSign64: (message, privateKey, hash) =>
    mobileCrypto.rsaSign64(message, privateKey, hash),
  rsaVerify: (signature, message, publicKey, hash) =>
    mobileCrypto.rsaVerify(signature, message, publicKey, hash),
  rsaVerify64: (signature, message, publicKey, hash) =>
    mobileCrypto.rsaVerify64(signature, message, publicKey, hash),
  calculateFileChecksum: (filePath) =>
    mobileCrypto.calculateFileChecksum(filePath),
  getRandomValues: (length) => mobileCrypto.getRandomValues(length),
  rsaImportKey: (jwk) => mobileCrypto.rsaImportKey(jwk),
  rsaExportKey: (pem) => mobileCrypto.rsaExportKey(pem),
};

export default MobileCryptoModule;
