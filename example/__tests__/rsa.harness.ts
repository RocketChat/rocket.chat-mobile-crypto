import { beforeAll, describe, expect, test } from 'react-native-harness';
import {
  rsaDecrypt,
  rsaEncrypt,
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  rsaSign,
  rsaVerify,
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
} from './__fixtures__/rsa';
import { unicodeVector } from './__fixtures__/crypto';
import {
  base64FromBuffer,
  bufferFromAscii,
  bufferFromBase64,
} from './__fixtures__/bytes';

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
    expect(await rsaDecrypt(fixedPrivateKey, RSA_FIXED_OAEP_CIPHERTEXT)).toBe(
      RSA_FIXED_PLAINTEXT
    );
  });

  test('decrypts an independent OAEP-SHA256 ciphertext of UTF-8 text', async () => {
    expect(await rsaDecrypt(fixedPrivateKey, RSA_UNICODE_OAEP_CIPHERTEXT)).toBe(
      unicodeVector.text
    );
  });

  test('round-trips UTF-8 text with the fixed keys', async () => {
    const ciphertext = await rsaEncrypt(fixedPublicKey, unicodeVector.text);
    expect(atob(ciphertext)).toHaveLength(256);
    expect(await rsaDecrypt(fixedPrivateKey, ciphertext)).toBe(
      unicodeVector.text
    );
  });

  test('keeps a leading byte order mark', async () => {
    const plaintext = '\uFEFFRocket.Chat';
    const ciphertext = await rsaEncrypt(fixedPublicKey, plaintext);
    expect(await rsaDecrypt(fixedPrivateKey, ciphertext)).toBe(plaintext);
  });

  test('encrypts with randomized OAEP padding', async () => {
    expect(await rsaEncrypt(fixedPublicKey, 'hello')).not.toBe(
      await rsaEncrypt(fixedPublicKey, 'hello')
    );
  });

  test('round-trips UTF-8 text with generated keys', async () => {
    const ciphertext = await rsaEncrypt(
      generatedKeys.publicKey,
      unicodeVector.text
    );
    expect(await rsaDecrypt(generatedKeys.privateKey, ciphertext)).toBe(
      unicodeVector.text
    );
  });

  test('signs to the exact PKCS#1 v1.5 SHA-256 known answer', async () => {
    const signature = await rsaSign(
      fixedPrivateKey,
      bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
      'SHA256'
    );
    expect(base64FromBuffer(signature)).toBe(RSA_FIXED_SIGNATURE);
  });

  test('verifies the known signature and rejects a changed message', async () => {
    const signature = bufferFromBase64(RSA_FIXED_SIGNATURE);
    expect(
      await rsaVerify(
        fixedPublicKey,
        signature,
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(true);
    expect(
      await rsaVerify(
        fixedPublicKey,
        signature,
        bufferFromAscii(`${RSA_FIXED_SIGN_MESSAGE} modified`),
        'SHA256'
      )
    ).toBe(false);
  });

  test('rejects a signature made with a different hash', async () => {
    const message = bufferFromAscii('message');
    const signature = await rsaSign(fixedPrivateKey, message, 'SHA1');
    expect(await rsaVerify(fixedPublicKey, signature, message, 'SHA256')).toBe(
      false
    );
  });

  test('returns false for a signature of the wrong length', async () => {
    const truncatedSignature = bufferFromBase64(
      RSA_FIXED_SIGNATURE.slice(0, 8)
    );
    expect(
      await rsaVerify(
        fixedPublicKey,
        truncatedSignature,
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(false);
  });

  test('returns false for a Raw signature longer than the key', async () => {
    const oversizedSignature = new Uint8Array(300).fill(1).buffer;
    expect(
      await rsaVerify(
        fixedPublicKey,
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
      const signature = await rsaSign(generatedKeys.privateKey, message, hash);
      expect(
        await rsaVerify(generatedKeys.publicKey, signature, message, hash)
      ).toBe(true);
    });
  }

  test('signs and verifies a precomputed digest with Raw', async () => {
    const digest = bufferFromBase64(
      'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ='
    );
    const signature = await rsaSign(fixedPrivateKey, digest, 'Raw');
    expect(await rsaVerify(fixedPublicKey, signature, digest, 'Raw')).toBe(
      true
    );
  });

  test('stays usable across concurrent operations', async () => {
    const message = bufferFromAscii(RSA_FIXED_SIGN_MESSAGE);
    const signatures = await Promise.all(
      Array.from({ length: 20 }, () =>
        rsaSign(fixedPrivateKey, message, 'SHA256')
      )
    );
    for (const signature of signatures) {
      expect(base64FromBuffer(signature)).toBe(RSA_FIXED_SIGNATURE);
    }
  });

  test('rejects an unsupported hash instead of throwing', async () => {
    const message = bufferFromAscii(RSA_FIXED_SIGN_MESSAGE);
    const unsupportedHash = 'unsupported' as RSAHashAlgorithm;
    const signing = rsaSign(fixedPrivateKey, message, unsupportedHash);
    const verifying = rsaVerify(
      fixedPublicKey,
      message,
      message,
      unsupportedHash
    );
    await expect(signing).rejects.toThrow(/"unsupported"/);
    await expect(verifying).rejects.toThrow(/"unsupported"/);
  });

  test('rejects a non-string argument instead of throwing', async () => {
    const notAString = 1 as unknown as string;
    const decrypting = rsaDecrypt(fixedPrivateKey, notAString);
    const encrypting = rsaEncrypt(fixedPublicKey, notAString);
    await expect(decrypting).rejects.toThrow();
    await expect(encrypting).rejects.toThrow();
  });

  test('rejects a ciphertext encrypted for a different private key', async () => {
    await expect(
      rsaDecrypt(generatedKeys.privateKey, RSA_FIXED_OAEP_CIPHERTEXT)
    ).rejects.toThrow();
  });

  test('rejects a ciphertext that is not base64', async () => {
    await expect(rsaDecrypt(fixedPrivateKey, 'not base64!')).rejects.toThrow();
  });

  test('rejects plaintext larger than the OAEP block can hold', async () => {
    await expect(rsaEncrypt(fixedPublicKey, 'x'.repeat(256))).rejects.toThrow();
  });
});
