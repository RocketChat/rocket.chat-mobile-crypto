import { beforeAll, describe, expect, test } from 'react-native-harness';
import {
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  type RSAHashAlgorithm,
  type RSAKeyPair,
  type RSAPrivateKey,
  type RSAPublicKey,
} from '@rocket.chat/mobile-crypto';
import {
  RSA_FIXED_OAEP_CIPHERTEXT,
  RSA_FIXED_PLAINTEXT,
  RSA_FIXED_PRIVATE_JWK,
  RSA_FIXED_PUBLIC_JWK,
  RSA_FIXED_SIGNATURE,
  RSA_FIXED_SIGN_MESSAGE,
  RSA_UNICODE_OAEP_CIPHERTEXT,
} from '../fixtures/rsa';
import { unicodeVector } from '../fixtures/crypto';
import {
  base64FromBuffer,
  bufferFromAscii,
  bufferFromBase64,
} from '../fixtures/bytes';

describe('RSA encryption and signatures', () => {
  let fixedPrivateKey: RSAPrivateKey;
  let fixedPublicKey: RSAPublicKey;
  let generatedKeys: RSAKeyPair;

  beforeAll(async () => {
    fixedPrivateKey = await rsaImportPrivateKey(RSA_FIXED_PRIVATE_JWK);
    fixedPublicKey = await rsaImportPublicKey(RSA_FIXED_PUBLIC_JWK);
    generatedKeys = await rsaGenerateKeys(2048);
  });

  test('decrypts the independent OAEP-SHA256 known-answer vector', async () => {
    expect(await fixedPrivateKey.decrypt(RSA_FIXED_OAEP_CIPHERTEXT)).toBe(
      RSA_FIXED_PLAINTEXT
    );
  });

  test('decrypts an independent OAEP-SHA256 ciphertext of UTF-8 text', async () => {
    expect(await fixedPrivateKey.decrypt(RSA_UNICODE_OAEP_CIPHERTEXT)).toBe(
      unicodeVector.text
    );
  });

  test('round-trips UTF-8 text with the fixed keys', async () => {
    const ciphertext = await fixedPublicKey.encrypt(unicodeVector.text);
    expect(atob(ciphertext)).toHaveLength(256);
    expect(await fixedPrivateKey.decrypt(ciphertext)).toBe(unicodeVector.text);
  });

  test('keeps a leading byte order mark', async () => {
    const plaintext = '\uFEFFRocket.Chat';
    const ciphertext = await fixedPublicKey.encrypt(plaintext);
    expect(await fixedPrivateKey.decrypt(ciphertext)).toBe(plaintext);
  });

  test('encrypts with randomized OAEP padding', async () => {
    expect(await fixedPublicKey.encrypt('hello')).not.toBe(
      await fixedPublicKey.encrypt('hello')
    );
  });

  test('round-trips UTF-8 text with generated keys', async () => {
    const ciphertext = await generatedKeys.publicKey.encrypt(
      unicodeVector.text
    );
    expect(await generatedKeys.privateKey.decrypt(ciphertext)).toBe(
      unicodeVector.text
    );
  });

  test('signs to the exact PKCS#1 v1.5 SHA-256 known answer', async () => {
    const signature = await fixedPrivateKey.sign(
      bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
      'SHA256'
    );
    expect(base64FromBuffer(signature)).toBe(RSA_FIXED_SIGNATURE);
  });

  test('verifies the known signature and rejects a changed message', async () => {
    const signature = bufferFromBase64(RSA_FIXED_SIGNATURE);
    expect(
      await fixedPublicKey.verify(
        signature,
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(true);
    expect(
      await fixedPublicKey.verify(
        signature,
        bufferFromAscii(`${RSA_FIXED_SIGN_MESSAGE} modified`),
        'SHA256'
      )
    ).toBe(false);
  });

  test('rejects a signature made with a different hash', async () => {
    const message = bufferFromAscii('message');
    const signature = await fixedPrivateKey.sign(message, 'SHA1');
    expect(await fixedPublicKey.verify(signature, message, 'SHA256')).toBe(
      false
    );
  });

  test('returns false for a signature of the wrong length', async () => {
    const truncatedSignature = bufferFromBase64(
      RSA_FIXED_SIGNATURE.slice(0, 8)
    );
    expect(
      await fixedPublicKey.verify(
        truncatedSignature,
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(false);
  });

  test('returns false for a Raw signature longer than the key', async () => {
    const oversizedSignature = new Uint8Array(300).fill(1).buffer;
    expect(
      await fixedPublicKey.verify(
        oversizedSignature,
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'Raw'
      )
    ).toBe(false);
  });

  for (const hash of [
    'SHA1',
    'SHA224',
    'SHA256',
    'SHA384',
    'SHA512',
  ] as const) {
    test(`signs and verifies non-UTF-8 bytes using ${hash}`, async () => {
      const message = bufferFromBase64('AAF/gP7/');
      const signature = await generatedKeys.privateKey.sign(message, hash);
      expect(
        await generatedKeys.publicKey.verify(signature, message, hash)
      ).toBe(true);
    });
  }

  test('signs and verifies a precomputed digest with Raw', async () => {
    const digest = bufferFromBase64(
      'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ='
    );
    const signature = await fixedPrivateKey.sign(digest, 'Raw');
    expect(await fixedPublicKey.verify(signature, digest, 'Raw')).toBe(true);
  });

  test('stays usable across concurrent operations', async () => {
    const message = bufferFromAscii(RSA_FIXED_SIGN_MESSAGE);
    const signatures = await Promise.all(
      Array.from({ length: 20 }, () => fixedPrivateKey.sign(message, 'SHA256'))
    );
    for (const signature of signatures) {
      expect(base64FromBuffer(signature)).toBe(RSA_FIXED_SIGNATURE);
    }
  });

  test('rejects an unsupported hash instead of throwing', async () => {
    const message = bufferFromAscii(RSA_FIXED_SIGN_MESSAGE);
    const unsupportedHash = 'unsupported' as RSAHashAlgorithm;
    const signing = fixedPrivateKey.sign(message, unsupportedHash);
    const verifying = fixedPublicKey.verify(message, message, unsupportedHash);
    await expect(signing).rejects.toThrow(/"unsupported"/);
    await expect(verifying).rejects.toThrow(/"unsupported"/);
  });

  test('rejects a non-string argument instead of throwing', async () => {
    const notAString = 1 as unknown as string;
    const decrypting = fixedPrivateKey.decrypt(notAString);
    const encrypting = fixedPublicKey.encrypt(notAString);
    await expect(decrypting).rejects.toThrow();
    await expect(encrypting).rejects.toThrow();
  });

  test('rejects a ciphertext encrypted for a different private key', async () => {
    await expect(
      generatedKeys.privateKey.decrypt(RSA_FIXED_OAEP_CIPHERTEXT)
    ).rejects.toThrow();
  });

  test('rejects a ciphertext that is not base64', async () => {
    await expect(fixedPrivateKey.decrypt('not base64!')).rejects.toThrow();
  });

  test('rejects plaintext larger than the OAEP block can hold', async () => {
    await expect(fixedPublicKey.encrypt('x'.repeat(256))).rejects.toThrow();
  });
});
