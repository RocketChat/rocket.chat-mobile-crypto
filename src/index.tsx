import { NitroModules } from 'react-native-nitro-modules';
import type { AESGCMCiphertext } from './specs/AESGCMCiphertext';
import type { AESKey } from './specs/AESKey.nitro';
import type { EncryptedFile } from './specs/EncryptedFile';
import type { MobileCrypto as MobileCryptoSpec } from './specs/MobileCrypto.nitro';
import type { PBKDF2HashAlgorithm } from './specs/PBKDF2HashAlgorithm';
import type { RSAHashAlgorithm } from './specs/RSAHashAlgorithm';
import type { RSAKeyPair as HybridRSAKeyPair } from './specs/RSAKeyPair';
import type { RSAPrivateKey as HybridRSAPrivateKey } from './specs/RSAPrivateKey.nitro';
import type { RSAPublicKey as HybridRSAPublicKey } from './specs/RSAPublicKey.nitro';
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
  decrypt(ciphertext: string): Promise<string>;
  sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>;
  exportJwk(): string;
}

export interface RSAPublicKey {
  encrypt(plaintext: string): Promise<string>;
  verify(
    signature: ArrayBuffer,
    message: ArrayBuffer,
    hash: RSAHashAlgorithm
  ): Promise<boolean>;
  exportJwk(): string;
}

export interface RSAKeyPair {
  publicKey: RSAPublicKey;
  privateKey: RSAPrivateKey;
}

const rejectingPrivateKey = (key: HybridRSAPrivateKey): RSAPrivateKey => ({
  decrypt: (ciphertext) => rejectOnThrow(() => key.decrypt(ciphertext)),
  sign: (message, hash) => rejectOnThrow(() => key.sign(message, hash)),
  exportJwk: () => key.exportJwk(),
});

const rejectingPublicKey = (key: HybridRSAPublicKey): RSAPublicKey => ({
  encrypt: (plaintext) => rejectOnThrow(() => key.encrypt(plaintext)),
  verify: (signature, message, hash) =>
    rejectOnThrow(() => key.verify(signature, message, hash)),
  exportJwk: () => key.exportJwk(),
});

const rejectingKeyPair = ({
  publicKey,
  privateKey,
}: HybridRSAKeyPair): RSAKeyPair => ({
  publicKey: rejectingPublicKey(publicKey),
  privateKey: rejectingPrivateKey(privateKey),
});

export type {
  AESGCMCiphertext,
  AESKey,
  EncryptedFile,
  PBKDF2HashAlgorithm,
  RSAHashAlgorithm,
  SHAAlgorithm,
};

export function sha(
  data: ArrayBuffer,
  algorithm: SHAAlgorithm
): Promise<ArrayBuffer> {
  return runBySize(
    [data],
    () => MobileCrypto.shaSync(data, algorithm),
    () => MobileCrypto.sha(data, algorithm)
  );
}

export function hmac256(
  data: ArrayBuffer,
  key: ArrayBuffer
): Promise<ArrayBuffer> {
  return runBySize(
    [data, key],
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

export function aesDeriveKey(
  passwordBase64: string,
  saltBase64: string,
  iterations: number,
  byteLength: number,
  hash: PBKDF2HashAlgorithm
): Promise<AESKey> {
  return rejectOnThrow(() =>
    MobileCrypto.aesDeriveKey(
      passwordBase64,
      saltBase64,
      iterations,
      byteLength,
      hash
    )
  );
}

export function aesGcmEncrypt(
  key: AESKey,
  plaintext: string
): Promise<AESGCMCiphertext> {
  return runBySize(
    [plaintext],
    () => MobileCrypto.aesGcmEncryptSync(key, plaintext),
    () => MobileCrypto.aesGcmEncrypt(key, plaintext)
  );
}

export function aesGcmDecrypt(
  key: AESKey,
  ciphertext: string,
  iv: string
): Promise<string> {
  return runBySize(
    [ciphertext],
    () => MobileCrypto.aesGcmDecryptSync(key, ciphertext, iv),
    () => MobileCrypto.aesGcmDecrypt(key, ciphertext, iv)
  );
}

export function aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string> {
  return runBySize(
    [plaintext],
    () => MobileCrypto.aesCbcEncryptSync(key, plaintext),
    () => MobileCrypto.aesCbcEncrypt(key, plaintext)
  );
}

export function aesCbcDecrypt(
  key: AESKey,
  ivAndCiphertext: string
): Promise<string> {
  return runBySize(
    [ivAndCiphertext],
    () => MobileCrypto.aesCbcDecryptSync(key, ivAndCiphertext),
    () => MobileCrypto.aesCbcDecrypt(key, ivAndCiphertext)
  );
}

export function aesEncryptFile(filePath: string): Promise<EncryptedFile> {
  return rejectOnThrow(() => MobileCrypto.aesEncryptFile(filePath));
}

export function aesDecryptFile(
  filePath: string,
  key: string,
  iv: string,
  sha256: string
): Promise<string> {
  return rejectOnThrow(() =>
    MobileCrypto.aesDecryptFile(filePath, key, iv, sha256)
  );
}

export function rsaGenerateKeys(keySize?: number): Promise<RSAKeyPair> {
  return rejectOnThrow(() => MobileCrypto.rsaGenerateKeys(keySize)).then(
    rejectingKeyPair
  );
}

export function rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey> {
  return rejectOnThrow(() => MobileCrypto.rsaImportPrivateKey(jwk)).then(
    rejectingPrivateKey
  );
}

export function rsaImportPublicKey(jwk: string): Promise<RSAPublicKey> {
  return rejectOnThrow(() => MobileCrypto.rsaImportPublicKey(jwk)).then(
    rejectingPublicKey
  );
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
