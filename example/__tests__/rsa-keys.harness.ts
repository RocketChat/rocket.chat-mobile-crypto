import { beforeAll, describe, expect, test } from 'react-native-harness';
import {
  rsaDecrypt64,
  rsaEncrypt64,
  rsaGenerateKeys,
  rsaImportKey,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  rsaSign64,
  rsaVerify64,
  type RSAHashAlgorithm,
  type RSAPrivateKey,
  type RSAPublicKey,
} from '@rocket.chat/mobile-crypto';
import {
  RSA_FIXED_JWK,
  RSA_FIXED_OAEP_CIPHERTEXT_B64,
  RSA_FIXED_PLAINTEXT,
  RSA_FIXED_PRIVATE_KEY,
  RSA_FIXED_PUBLIC_KEY,
  RSA_FIXED_SIGNATURE_B64,
  RSA_FIXED_SIGN_MESSAGE,
} from '../fixtures/rsa';
import {
  base64FromBuffer,
  bufferFromAscii,
  bufferFromBase64,
} from './__fixtures__/bytes';

describe('Imported RSA key objects', () => {
  let fixedPrivateKey: RSAPrivateKey;
  let fixedPublicKey: RSAPublicKey;

  beforeAll(async () => {
    fixedPrivateKey = await rsaImportPrivateKey(RSA_FIXED_PRIVATE_KEY);
    fixedPublicKey = await rsaImportPublicKey(RSA_FIXED_PUBLIC_KEY);
  });

  test('decrypts the independent OAEP-SHA256 known-answer vector', async () => {
    const plaintext = await fixedPrivateKey.decrypt(
      bufferFromBase64(RSA_FIXED_OAEP_CIPHERTEXT_B64)
    );
    expect(base64FromBuffer(plaintext)).toBe(btoa(RSA_FIXED_PLAINTEXT));
  });

  test('signs to the exact PKCS#1 v1.5 SHA-256 known answer', async () => {
    const signature = await fixedPrivateKey.sign(
      bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
      'SHA256'
    );
    expect(base64FromBuffer(signature)).toBe(RSA_FIXED_SIGNATURE_B64);
  });

  test('verifies the known signature and rejects a changed message', async () => {
    const signature = bufferFromBase64(RSA_FIXED_SIGNATURE_B64);
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
      RSA_FIXED_SIGNATURE_B64.slice(0, 8)
    );
    expect(
      await fixedPublicKey.verify(
        truncatedSignature,
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(false);
  });

  test('encrypts ciphertext that the PEM string API decrypts', async () => {
    const ciphertext = await fixedPublicKey.encrypt(
      bufferFromBase64('AAF/gP7/')
    );
    expect(
      await rsaDecrypt64(base64FromBuffer(ciphertext), RSA_FIXED_PRIVATE_KEY)
    ).toBe('AAF/gP7/');
  });

  test('decrypts ciphertext produced by the PEM string API', async () => {
    const ciphertext = await rsaEncrypt64('AAF/gP7/', RSA_FIXED_PUBLIC_KEY);
    const plaintext = await fixedPrivateKey.decrypt(
      bufferFromBase64(ciphertext)
    );
    expect(base64FromBuffer(plaintext)).toBe('AAF/gP7/');
  });

  for (const hash of [
    'SHA1',
    'SHA224',
    'SHA256',
    'SHA384',
    'SHA512',
  ] as const) {
    test(`produces the same ${hash} signature as the PEM string API`, async () => {
      const message = 'AAF/gP7/';
      const signature = await fixedPrivateKey.sign(
        bufferFromBase64(message),
        hash
      );
      expect(base64FromBuffer(signature)).toBe(
        await rsaSign64(message, RSA_FIXED_PRIVATE_KEY, hash)
      );
      expect(
        await rsaVerify64(
          base64FromBuffer(signature),
          message,
          RSA_FIXED_PUBLIC_KEY,
          hash
        )
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
      expect(base64FromBuffer(signature)).toBe(RSA_FIXED_SIGNATURE_B64);
    }
  });

  test('imports keys generated on the device', async () => {
    const keys = await rsaGenerateKeys(2048);
    const privateKey = await rsaImportPrivateKey(keys.private);
    const publicKey = await rsaImportPublicKey(keys.public);
    const plaintext = bufferFromAscii('generated key');
    const decrypted = await privateKey.decrypt(
      await publicKey.encrypt(plaintext)
    );
    expect(base64FromBuffer(decrypted)).toBe(base64FromBuffer(plaintext));
  });

  test('imports a PKCS#1 public key built from a JWK', async () => {
    const publicKey = await rsaImportPublicKey(
      await rsaImportKey(RSA_FIXED_JWK)
    );
    expect(
      await publicKey.verify(
        bufferFromBase64(RSA_FIXED_SIGNATURE_B64),
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(true);
  });

  test('rejects ciphertext encrypted for a different key', async () => {
    const keys = await rsaGenerateKeys(2048);
    const otherKey = await rsaImportPrivateKey(keys.private);
    await expect(
      otherKey.decrypt(bufferFromBase64(RSA_FIXED_OAEP_CIPHERTEXT_B64))
    ).rejects.toThrow();
  });

  test('rejects plaintext larger than the OAEP block can hold', async () => {
    await expect(
      fixedPublicKey.encrypt(new Uint8Array(256).buffer)
    ).rejects.toThrow();
  });

  test('rejects an unknown hash instead of throwing', async () => {
    const message = bufferFromAscii('message');
    const unknownHash = 'bogus' as RSAHashAlgorithm;
    const signing = fixedPrivateKey.sign(message, unknownHash);
    const verifying = fixedPublicKey.verify(message, message, unknownHash);
    await expect(signing).rejects.toThrow();
    await expect(verifying).rejects.toThrow();
  });

  test('rejects a non-buffer argument instead of throwing', async () => {
    const notABuffer = 'not a buffer' as unknown as ArrayBuffer;
    const decrypting = fixedPrivateKey.decrypt(notABuffer);
    const encrypting = fixedPublicKey.encrypt(notABuffer);
    await expect(decrypting).rejects.toThrow();
    await expect(encrypting).rejects.toThrow();
  });

  test('rejects an invalid private key PEM', async () => {
    await expect(rsaImportPrivateKey('invalid PEM')).rejects.toThrow();
  });

  test('rejects an invalid public key PEM', async () => {
    await expect(rsaImportPublicKey('invalid PEM')).rejects.toThrow();
  });
});
