import { NitroModules } from 'react-native-nitro-modules';
import type { AESGCMCiphertext } from './specs/AESGCMCiphertext';
import type { AESKey } from './specs/AESKey.nitro';
import type { EncryptedFile } from './specs/EncryptedFile';
import type { MobileCrypto as MobileCryptoSpec } from './specs/MobileCrypto.nitro';
import type { PBKDF2HashAlgorithm } from './specs/PBKDF2HashAlgorithm';
import type { RSAHashAlgorithm } from './specs/RSAHashAlgorithm';
import type { RSAKeyPair } from './specs/RSAKeyPair';
import type { RSAPrivateKey } from './specs/RSAPrivateKey.nitro';
import type { RSAPublicKey } from './specs/RSAPublicKey.nitro';
import type { SHAAlgorithm } from './specs/SHAAlgorithm';

const MobileCrypto =
  NitroModules.createHybridObject<MobileCryptoSpec>('MobileCrypto');

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
  sizedInputs: () => SizedInput[],
  runSync: () => T,
  runAsync: () => Promise<T>
): Promise<T> =>
  rejectOnThrow(() =>
    sizedInputs().reduce((total, input) => total + inputSize(input), 0) <=
    SYNC_INPUT_LIMIT
      ? runSync()
      : runAsync()
  );

export type {
  AESGCMCiphertext,
  AESKey,
  EncryptedFile,
  PBKDF2HashAlgorithm,
  RSAHashAlgorithm,
  RSAKeyPair,
  RSAPrivateKey,
  RSAPublicKey,
  SHAAlgorithm,
};

export function sha(
  data: ArrayBuffer,
  algorithm: SHAAlgorithm
): Promise<ArrayBuffer> {
  return runBySize(
    () => [data],
    () => MobileCrypto.shaSync(data, algorithm),
    () => MobileCrypto.sha(data, algorithm)
  );
}

export function hmac256(
  data: ArrayBuffer,
  key: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    () => [data, key],
    () => MobileCrypto.hmac256Sync(data, key),
    () => MobileCrypto.hmac256(data, key)
  );
}

export function aesGenerateKey(byteLength: number): AESKey {
  return MobileCrypto.aesGenerateKey(byteLength);
}

export function aesImportKey(base64Url: string): AESKey {
  return MobileCrypto.aesImportKey(base64Url);
}

export interface AESDeriveKeyOptions {
  iterations: number;
  byteLength: number;
  hash: PBKDF2HashAlgorithm;
}

export function aesDeriveKey(
  passwordBase64: string,
  saltBase64: string,
  options: AESDeriveKeyOptions
): Promise<AESKey> {
  return rejectOnThrow(() =>
    MobileCrypto.aesDeriveKey(
      passwordBase64,
      saltBase64,
      options.iterations,
      options.byteLength,
      options.hash
    )
  );
}

export function aesGcmEncrypt(
  key: AESKey,
  plaintext: string
): Promise<AESGCMCiphertext> {
  return runBySize(
    () => [plaintext],
    () => MobileCrypto.aesGcmEncryptSync(key, plaintext),
    () => MobileCrypto.aesGcmEncrypt(key, plaintext)
  );
}

export function aesGcmDecrypt(
  key: AESKey,
  encrypted: AESGCMCiphertext
): Promise<string> {
  return runBySize(
    () => [encrypted.ciphertext],
    () => MobileCrypto.aesGcmDecryptSync(key, encrypted),
    () => MobileCrypto.aesGcmDecrypt(key, encrypted)
  );
}

export function aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string> {
  return runBySize(
    () => [plaintext],
    () => MobileCrypto.aesCbcEncryptSync(key, plaintext),
    () => MobileCrypto.aesCbcEncrypt(key, plaintext)
  );
}

export function aesCbcDecrypt(
  key: AESKey,
  ivAndCiphertext: string
): Promise<string> {
  return runBySize(
    () => [ivAndCiphertext],
    () => MobileCrypto.aesCbcDecryptSync(key, ivAndCiphertext),
    () => MobileCrypto.aesCbcDecrypt(key, ivAndCiphertext)
  );
}

export function aesEncryptFile(filePath: string): Promise<EncryptedFile> {
  return rejectOnThrow(() => MobileCrypto.aesEncryptFile(filePath));
}

export function aesDecryptFile(file: EncryptedFile): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.aesDecryptFile(file));
}

export function rsaGenerateKeys(keySize?: number): Promise<RSAKeyPair> {
  return rejectOnThrow(() => MobileCrypto.rsaGenerateKeys(keySize));
}

export function rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey> {
  return rejectOnThrow(() => MobileCrypto.rsaImportPrivateKey(jwk));
}

export function rsaImportPublicKey(jwk: string): Promise<RSAPublicKey> {
  return rejectOnThrow(() => MobileCrypto.rsaImportPublicKey(jwk));
}

export function rsaEncrypt(
  publicKey: RSAPublicKey,
  plaintext: string
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaEncrypt(publicKey, plaintext));
}

export function rsaDecrypt(
  privateKey: RSAPrivateKey,
  ciphertext: string
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaDecrypt(privateKey, ciphertext));
}

export function rsaSign(
  privateKey: RSAPrivateKey,
  message: ArrayBuffer,
  hash: RSAHashAlgorithm
): Promise<ArrayBuffer> {
  return rejectOnThrow(() => MobileCrypto.rsaSign(privateKey, message, hash));
}

export function rsaVerify(
  publicKey: RSAPublicKey,
  signature: ArrayBuffer,
  message: ArrayBuffer,
  hash: RSAHashAlgorithm
): Promise<boolean> {
  return rejectOnThrow(() =>
    MobileCrypto.rsaVerify(publicKey, signature, message, hash)
  );
}

export function rsaVerifyJwt(
  publicKey: RSAPublicKey,
  jwt: string
): Promise<string> {
  return rejectOnThrow(() => MobileCrypto.rsaVerifyJwt(publicKey, jwt));
}

export function randomUuid(): string {
  return MobileCrypto.randomUuid();
}

export function randomKey(length: number): string {
  return MobileCrypto.randomKey(length);
}

export function randomBytes(size: number): ArrayBuffer {
  return MobileCrypto.randomBytes(size);
}
