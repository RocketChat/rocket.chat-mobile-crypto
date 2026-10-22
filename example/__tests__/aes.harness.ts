import { describe, expect, test } from 'react-native-harness';
import {
  aesDecrypt,
  aesEncrypt,
  aesGcmDecrypt,
  aesGcmEncrypt,
} from '@rocket.chat/mobile-crypto';
import { cbcVectors, gcmVectors } from './__fixtures__/crypto';

describe('AES-CBC with PKCS7 padding', () => {
  for (const vector of cbcVectors) {
    test(`encrypts with a ${vector.bits}-bit key to a fixed ciphertext`, async () => {
      expect(
        await aesEncrypt(vector.plaintext, vector.keyHex, vector.ivHex)
      ).toBe(vector.ciphertext);
    });

    test(`decrypts a fixed ciphertext with a ${vector.bits}-bit key`, async () => {
      expect(
        await aesDecrypt(vector.ciphertext, vector.keyHex, vector.ivHex)
      ).toBe(vector.plaintext);
    });
  }

  test('round-trips binary input spanning multiple AES blocks', async () => {
    const plaintext = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=';
    const key = '0123456789abcdef'.repeat(4);
    const iv = 'fedcba9876543210fedcba9876543210';
    const encrypted = await aesEncrypt(plaintext, key, iv);

    expect(encrypted).not.toBe(plaintext);
    expect(await aesDecrypt(encrypted, key, iv)).toBe(plaintext);
  });

  test('rejects an invalid key when encrypting', async () => {
    await expect(
      aesEncrypt('aGVsbG8=', '00', '00'.repeat(16))
    ).rejects.toThrow();
  });

  test('rejects an invalid key when decrypting', async () => {
    await expect(
      aesDecrypt('AAECAwQFBgcICQoLDA0ODw==', '00', '00'.repeat(16))
    ).rejects.toThrow();
  });

  test('returns null for empty plaintext and ciphertext', async () => {
    const key = '00'.repeat(32);
    const iv = '00'.repeat(16);
    expect(await aesEncrypt('', key, iv)).toBeNull();
    expect(await aesDecrypt('', key, iv)).toBeNull();
  });
});

describe('AES-256-GCM authenticated encryption', () => {
  for (const vector of gcmVectors) {
    test(`encrypts the ${vector.name} including the authentication tag`, async () => {
      expect(
        await aesGcmEncrypt(vector.plaintext, vector.keyHex, vector.ivHex)
      ).toBe(vector.ciphertext);
    });

    test(`decrypts the ${vector.name}`, async () => {
      expect(
        await aesGcmDecrypt(vector.ciphertext, vector.keyHex, vector.ivHex)
      ).toBe(vector.plaintext);
    });

    test(`rejects modified ciphertext for the ${vector.name}`, async () => {
      expect(
        await aesGcmDecrypt(
          vector.tamperedCiphertext,
          vector.keyHex,
          vector.ivHex
        )
      ).toBeNull();
    });

    test(`rejects a modified authentication tag for the ${vector.name}`, async () => {
      expect(
        await aesGcmDecrypt(vector.tamperedTag, vector.keyHex, vector.ivHex)
      ).toBeNull();
    });

    test(`rejects the wrong key for the ${vector.name}`, async () => {
      expect(
        await aesGcmDecrypt(vector.ciphertext, '11'.repeat(32), vector.ivHex)
      ).toBeNull();
    });

    test(`rejects the wrong IV for the ${vector.name}`, async () => {
      expect(
        await aesGcmDecrypt(vector.ciphertext, vector.keyHex, '11'.repeat(12))
      ).toBeNull();
    });
  }

  test('returns null for ciphertext shorter than an authentication tag', async () => {
    expect(
      await aesGcmDecrypt('aGVsbG8=', '00'.repeat(32), '00'.repeat(12))
    ).toBeNull();
  });

  test('returns null for an invalid encryption key', async () => {
    expect(await aesGcmEncrypt('aGVsbG8=', '00', '00'.repeat(12))).toBeNull();
  });

  test('returns null for empty plaintext and ciphertext', async () => {
    const key = '00'.repeat(32);
    const iv = '00'.repeat(12);
    expect(await aesGcmEncrypt('', key, iv)).toBeNull();
    expect(await aesGcmDecrypt('', key, iv)).toBeNull();
  });
});

describe('inputs above the synchronous size limit', () => {
  const plaintext = 'AAECAwQF'.repeat(6000);
  const key = '0123456789abcdef'.repeat(4);

  test('round-trips large input with AES-CBC', async () => {
    const iv = 'fedcba9876543210fedcba9876543210';
    const encrypted = await aesEncrypt(plaintext, key, iv);
    expect(await aesDecrypt(encrypted, key, iv)).toBe(plaintext);
  });

  test('round-trips large input with AES-GCM', async () => {
    const iv = '00112233445566778899aabb';
    const encrypted = await aesGcmEncrypt(plaintext, key, iv);
    expect(await aesGcmDecrypt(encrypted, key, iv)).toBe(plaintext);
  });
});
