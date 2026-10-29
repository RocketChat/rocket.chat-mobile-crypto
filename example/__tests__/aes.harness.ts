import { describe, expect, test } from 'react-native-harness';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  aesDeriveKey,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesGenerateKey,
  aesImportKey,
  type PBKDF2HashAlgorithm,
} from '@rocket.chat/mobile-crypto';
import {
  binaryPbkdf2Vector,
  cbcVectors,
  emptyPlaintextVectors,
  gcmVectors,
  invalidUtf8Vectors,
  latin1Pbkdf2Vector,
  passwordBase64,
  pbkdf2Vectors,
  rfc6070Pbkdf2Vector,
  saltBase64,
  unicodePbkdf2Vector,
  unicodeVector,
  zeroKey,
} from './__fixtures__/crypto';

const decodedLength = (base64: string) => atob(base64).length;
const otherKey = 'ERERERERERERERERERERERERERERERERERERERERERE';
const largePlaintext = 'Rocket.Chat 🔐 '.repeat(4000);

describe('AES keys', () => {
  for (const byteLength of [16, 24, 32]) {
    test(`generates a fresh ${byteLength}-byte key`, () => {
      const exported = aesGenerateKey(byteLength).exportBase64Url();
      expect(exported).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(exported).toHaveLength(Math.ceil((byteLength * 4) / 3));
      expect(aesGenerateKey(byteLength).exportBase64Url()).not.toBe(exported);
    });
  }

  for (const vector of cbcVectors) {
    test(`exports an imported ${vector.bits}-bit key unchanged`, () => {
      expect(aesImportKey(vector.key).exportBase64Url()).toBe(vector.key);
    });
  }

  test('accepts padded base64url and exports it unpadded', () => {
    expect(aesImportKey(`${cbcVectors[0]!.key}==`).exportBase64Url()).toBe(
      cbcVectors[0]!.key
    );
  });

  for (const byteLength of [0, 15, 17, 31, 33, 64]) {
    test(`refuses to generate a ${byteLength}-byte key`, () => {
      expect(() => aesGenerateKey(byteLength)).toThrow();
    });
  }

  test('refuses to import a key that decodes to an invalid length', () => {
    expect(() => aesImportKey('AAECAwQFBgcICQoLDA0O')).toThrow();
  });

  test('refuses to import a key that is not base64url', () => {
    expect(() => aesImportKey('not base64url!')).toThrow();
  });
});

describe('PBKDF2 key derivation', () => {
  for (const vector of pbkdf2Vectors) {
    test(`derives ${vector.byteLength} bytes with ${vector.algorithm}`, async () => {
      const key = await aesDeriveKey(
        passwordBase64,
        saltBase64,
        1000,
        vector.byteLength,
        vector.algorithm
      );
      expect(key.exportBase64Url()).toBe(vector.expected);
    });
  }

  test('matches the single-iteration RFC 6070 SHA-1 vector', async () => {
    const key = await aesDeriveKey(passwordBase64, saltBase64, 1, 16, 'SHA1');
    expect(key.exportBase64Url()).toBe(rfc6070Pbkdf2Vector);
  });

  test('preserves null bytes in the password and salt', async () => {
    const key = await aesDeriveKey(
      binaryPbkdf2Vector.passwordBase64,
      binaryPbkdf2Vector.saltBase64,
      4096,
      16,
      'SHA256'
    );
    expect(key.exportBase64Url()).toBe(binaryPbkdf2Vector.expected);
  });

  test('derives from UTF-8 password bytes', async () => {
    const key = await aesDeriveKey(
      unicodeVector.base64,
      saltBase64,
      1000,
      32,
      'SHA256'
    );
    expect(key.exportBase64Url()).toBe(unicodePbkdf2Vector);
  });

  test('derives from Latin-1 password bytes', async () => {
    const key = await aesDeriveKey(
      latin1Pbkdf2Vector.passwordBase64,
      saltBase64,
      1000,
      32,
      'SHA256'
    );
    expect(key.exportBase64Url()).toBe(latin1Pbkdf2Vector.expected);
  });

  test('rejects a password that is not base64', async () => {
    await expect(
      aesDeriveKey('not base64!', saltBase64, 1000, 32, 'SHA256')
    ).rejects.toThrow();
  });

  test('derives a key that encrypts and decrypts', async () => {
    const key = await aesDeriveKey(
      passwordBase64,
      saltBase64,
      1000,
      32,
      'SHA256'
    );
    const { ciphertext, iv } = await aesGcmEncrypt(key, 'derived');
    expect(await aesGcmDecrypt(key, ciphertext, iv)).toBe('derived');
  });

  test('rejects an unsupported hash algorithm', async () => {
    await expect(
      aesDeriveKey(
        passwordBase64,
        saltBase64,
        1000,
        32,
        'unsupported' as PBKDF2HashAlgorithm
      )
    ).rejects.toThrow();
  });
});

describe('AES-GCM', () => {
  for (const vector of gcmVectors) {
    test(`decrypts the ${vector.name}`, async () => {
      expect(
        await aesGcmDecrypt(
          aesImportKey(vector.key),
          vector.ciphertext,
          vector.iv
        )
      ).toBe(vector.plaintext);
    });

    test(`rejects modified ciphertext for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(
          aesImportKey(vector.key),
          vector.tamperedCiphertext,
          vector.iv
        )
      ).rejects.toThrow();
    });

    test(`rejects a modified authentication tag for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(aesImportKey(vector.key), vector.tamperedTag, vector.iv)
      ).rejects.toThrow();
    });

    test(`rejects the wrong key for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(aesImportKey(otherKey), vector.ciphertext, vector.iv)
      ).rejects.toThrow();
    });

    test(`rejects the wrong IV for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(
          aesImportKey(vector.key),
          vector.ciphertext,
          'ERERERERERERERER'
        )
      ).rejects.toThrow();
    });

    if (!vector.plaintext.includes('\0')) {
      test(`round-trips the ${vector.name} plaintext`, async () => {
        const key = aesImportKey(vector.key);
        const { ciphertext, iv } = await aesGcmEncrypt(key, vector.plaintext);
        expect(decodedLength(ciphertext)).toBe(
          decodedLength(vector.ciphertext)
        );
        expect(await aesGcmDecrypt(key, ciphertext, iv)).toBe(vector.plaintext);
      });
    }
  }

  test('uses a fresh 12-byte IV on every call', async () => {
    const key = aesImportKey(zeroKey);
    const first = await aesGcmEncrypt(key, 'hello');
    const second = await aesGcmEncrypt(key, 'hello');
    expect(decodedLength(first.iv)).toBe(12);
    expect(decodedLength(second.iv)).toBe(12);
    expect(second.iv).not.toBe(first.iv);
    expect(second.ciphertext).not.toBe(first.ciphertext);
  });

  test('decrypts an empty plaintext from only the authentication tag', async () => {
    expect(
      await aesGcmDecrypt(
        aesImportKey(zeroKey),
        emptyPlaintextVectors.gcmCiphertext,
        emptyPlaintextVectors.gcmIv
      )
    ).toBe('');
  });

  test('encrypts an empty plaintext to only the authentication tag', async () => {
    const { ciphertext } = await aesGcmEncrypt(aesImportKey(zeroKey), '');
    expect(decodedLength(ciphertext)).toBe(16);
  });

  test('rejects ciphertext shorter than an authentication tag', async () => {
    await expect(
      aesGcmDecrypt(aesImportKey(zeroKey), 'aGVsbG8=', 'AAAAAAAAAAAAAAAA')
    ).rejects.toThrow();
  });

  test('rejects ciphertext that is not base64', async () => {
    await expect(
      aesGcmDecrypt(aesImportKey(zeroKey), 'not base64!', 'AAAAAAAAAAAAAAAA')
    ).rejects.toThrow();
  });

  test('rejects an IV that is not base64', async () => {
    await expect(
      aesGcmDecrypt(
        aesImportKey(zeroKey),
        emptyPlaintextVectors.gcmCiphertext,
        'not base64!'
      )
    ).rejects.toThrow();
  });

  test('rejects plaintext that is not valid UTF-8', async () => {
    await expect(
      aesGcmDecrypt(
        aesImportKey(zeroKey),
        invalidUtf8Vectors.gcmCiphertext,
        invalidUtf8Vectors.gcmIv
      )
    ).rejects.toThrow();
  });
});

describe('AES-CBC with PKCS7 padding', () => {
  for (const vector of cbcVectors) {
    test(`decrypts a fixed ciphertext with a ${vector.bits}-bit key`, async () => {
      expect(
        await aesCbcDecrypt(aesImportKey(vector.key), vector.ivAndCiphertext)
      ).toBe(vector.plaintext);
    });

    test(`round-trips with a ${vector.bits}-bit key`, async () => {
      const key = aesImportKey(vector.key);
      const ivAndCiphertext = await aesCbcEncrypt(key, vector.plaintext);
      expect(decodedLength(ivAndCiphertext)).toBe(
        decodedLength(vector.ivAndCiphertext)
      );
      expect(await aesCbcDecrypt(key, ivAndCiphertext)).toBe(vector.plaintext);
    });
  }

  test('prefixes a fresh 16-byte IV on every call', async () => {
    const key = aesImportKey(zeroKey);
    const first = atob(await aesCbcEncrypt(key, 'hello'));
    const second = atob(await aesCbcEncrypt(key, 'hello'));
    expect(first).toHaveLength(32);
    expect(second.slice(0, 16)).not.toBe(first.slice(0, 16));
  });

  test('round-trips UTF-8 text spanning multiple blocks', async () => {
    const key = aesImportKey(zeroKey);
    const ivAndCiphertext = await aesCbcEncrypt(key, unicodeVector.text);
    expect(await aesCbcDecrypt(key, ivAndCiphertext)).toBe(unicodeVector.text);
  });

  test('decrypts an empty plaintext from a single padding block', async () => {
    expect(
      await aesCbcDecrypt(
        aesImportKey(zeroKey),
        emptyPlaintextVectors.cbcIvAndCiphertext
      )
    ).toBe('');
  });

  test('rejects the wrong key', async () => {
    await expect(
      aesCbcDecrypt(aesImportKey(otherKey), cbcVectors[2]!.ivAndCiphertext)
    ).rejects.toThrow();
  });

  test('rejects input shorter than an IV and one block', async () => {
    await expect(
      aesCbcDecrypt(aesImportKey(zeroKey), 'AAAAAAAAAAAAAAAAAAAAAA==')
    ).rejects.toThrow();
  });

  test('rejects input that is not base64', async () => {
    await expect(
      aesCbcDecrypt(aesImportKey(zeroKey), 'not base64!')
    ).rejects.toThrow();
  });

  test('rejects plaintext that is not valid UTF-8', async () => {
    await expect(
      aesCbcDecrypt(
        aesImportKey(zeroKey),
        invalidUtf8Vectors.cbcIvAndCiphertext
      )
    ).rejects.toThrow();
  });
});

describe('inputs above the synchronous size limit', () => {
  test('round-trips large input with AES-GCM', async () => {
    const key = aesGenerateKey(32);
    const { ciphertext, iv } = await aesGcmEncrypt(key, largePlaintext);
    expect(await aesGcmDecrypt(key, ciphertext, iv)).toBe(largePlaintext);
  });

  test('round-trips large input with AES-CBC', async () => {
    const key = aesGenerateKey(32);
    const ivAndCiphertext = await aesCbcEncrypt(key, largePlaintext);
    expect(await aesCbcDecrypt(key, ivAndCiphertext)).toBe(largePlaintext);
  });

  test('rejects a tampered large AES-GCM ciphertext', async () => {
    const key = aesGenerateKey(32);
    const { ciphertext, iv } = await aesGcmEncrypt(key, largePlaintext);
    const tampered = `${ciphertext[0] === 'A' ? 'B' : 'A'}${ciphertext.slice(1)}`;
    await expect(aesGcmDecrypt(key, tampered, iv)).rejects.toThrow();
  });
});
