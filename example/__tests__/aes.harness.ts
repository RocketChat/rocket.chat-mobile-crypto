import { Platform } from 'react-native';
import { describe, expect, test } from 'react-native-harness';
import {
  type AESGCMCiphertext,
  type AESKey,
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
  aes192Key,
  binaryPbkdf2Vector,
  cbcVectors,
  emptyPlaintextVectors,
  fileVector,
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
} from '../fixtures/crypto';

const decodedLength = (base64: string) => atob(base64).length;
const otherKey = 'ERERERERERERERERERERERERERERERERERERERERERE';
const largePlaintext = 'Rocket.Chat 🔐 '.repeat(4000);
const byteOrderMarkPlaintext = '\uFEFFRocket.Chat';
const toBase64Url = (base64: string) =>
  base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/[=]+$/, '');
const toStandardAlphabet = (base64Url: string) =>
  base64Url.replace(/-/g, '+').replace(/_/g, '/');
const wrapLines = (base64: string) =>
  `${base64.slice(0, 8)}\n${base64.slice(8)}`;

describe('AES keys', () => {
  for (const byteLength of [16, 32]) {
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

  for (const byteLength of [0, 15, 17, 24, 31, 33, 64]) {
    test(`refuses to generate a ${byteLength}-byte key`, () => {
      expect(() => aesGenerateKey(byteLength)).toThrow();
    });
  }

  test('refuses to import a key that decodes to an invalid length', () => {
    expect(() => aesImportKey('AAECAwQFBgcICQoLDA0O')).toThrow();
  });

  test('refuses to import a 24-byte key', () => {
    expect(() => aesImportKey(aes192Key)).toThrow();
  });

  test('refuses to import a key that is not base64url', () => {
    expect(() => aesImportKey('not base64url!')).toThrow();
  });

  test('refuses to import a key in the standard base64 alphabet', () => {
    const standardKey = toStandardAlphabet(fileVector.key);
    expect(standardKey).not.toBe(fileVector.key);
    expect(() => aesImportKey(standardKey)).toThrow();
  });

  test('refuses to import a key with the wrong padding', () => {
    expect(() => aesImportKey(`${cbcVectors[0]!.key}=`)).toThrow();
  });

  test('refuses to import a key with whitespace', () => {
    expect(() => aesImportKey(` ${cbcVectors[0]!.key}`)).toThrow();
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

  test('rejects a 24-byte key length', async () => {
    await expect(
      aesDeriveKey(passwordBase64, saltBase64, 1000, 24, 'SHA256')
    ).rejects.toThrow();
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
    const encrypted = await aesGcmEncrypt(key, 'derived');
    expect(await aesGcmDecrypt(key, encrypted)).toBe('derived');
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
        await aesGcmDecrypt(aesImportKey(vector.key), {
          ciphertext: vector.ciphertext,
          iv: vector.iv,
        })
      ).toBe(vector.plaintext);
    });

    test(`rejects modified ciphertext for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(aesImportKey(vector.key), {
          ciphertext: vector.tamperedCiphertext,
          iv: vector.iv,
        })
      ).rejects.toThrow();
    });

    test(`rejects a modified authentication tag for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(aesImportKey(vector.key), {
          ciphertext: vector.tamperedTag,
          iv: vector.iv,
        })
      ).rejects.toThrow();
    });

    test(`rejects the wrong key for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(aesImportKey(otherKey), {
          ciphertext: vector.ciphertext,
          iv: vector.iv,
        })
      ).rejects.toThrow();
    });

    test(`rejects the wrong IV for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecrypt(aesImportKey(vector.key), {
          ciphertext: vector.ciphertext,
          iv: 'ERERERERERERERER',
        })
      ).rejects.toThrow();
    });

    if (Platform.OS === 'ios' || !vector.plaintext.includes('\0')) {
      test(`round-trips the ${vector.name} plaintext`, async () => {
        const key = aesImportKey(vector.key);
        const encrypted = await aesGcmEncrypt(key, vector.plaintext);
        expect(decodedLength(encrypted.ciphertext)).toBe(
          decodedLength(vector.ciphertext)
        );
        expect(await aesGcmDecrypt(key, encrypted)).toBe(vector.plaintext);
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
      await aesGcmDecrypt(aesImportKey(zeroKey), {
        ciphertext: emptyPlaintextVectors.gcmCiphertext,
        iv: emptyPlaintextVectors.gcmIv,
      })
    ).toBe('');
  });

  test('encrypts an empty plaintext to only the authentication tag', async () => {
    const { ciphertext } = await aesGcmEncrypt(aesImportKey(zeroKey), '');
    expect(decodedLength(ciphertext)).toBe(16);
  });

  test('rejects ciphertext shorter than an authentication tag', async () => {
    await expect(
      aesGcmDecrypt(aesImportKey(zeroKey), {
        ciphertext: 'aGVsbG8=',
        iv: 'AAAAAAAAAAAAAAAA',
      })
    ).rejects.toThrow();
  });

  test('rejects a missing ciphertext object instead of throwing', async () => {
    const missing = undefined as unknown as AESGCMCiphertext;
    const decrypting = aesGcmDecrypt(aesImportKey(zeroKey), missing);
    await expect(decrypting).rejects.toThrow();
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
      aesCbcDecrypt(aesImportKey(otherKey), cbcVectors[1]!.ivAndCiphertext)
    ).rejects.toThrow();
  });

  test('rejects input shorter than an IV and one block', async () => {
    await expect(
      aesCbcDecrypt(aesImportKey(zeroKey), 'AAAAAAAAAAAAAAAAAAAAAA==')
    ).rejects.toThrow();
  });
});

const gcmIvVector = gcmVectors[2]!;

const base64Inputs = [
  {
    name: 'an AES-GCM ciphertext',
    valid: emptyPlaintextVectors.gcmCiphertext,
    decrypt: (ciphertext: string) =>
      aesGcmDecrypt(aesImportKey(zeroKey), {
        ciphertext,
        iv: emptyPlaintextVectors.gcmIv,
      }),
  },
  {
    name: 'an AES-GCM IV',
    valid: gcmIvVector.iv,
    decrypt: (iv: string) =>
      aesGcmDecrypt(aesImportKey(gcmIvVector.key), {
        ciphertext: gcmIvVector.ciphertext,
        iv,
      }),
  },
  {
    name: 'an AES-CBC IV and ciphertext',
    valid: emptyPlaintextVectors.cbcIvAndCiphertext,
    decrypt: (ivAndCiphertext: string) =>
      aesCbcDecrypt(aesImportKey(zeroKey), ivAndCiphertext),
  },
];

const base64Malformations = [
  ['that is not base64', () => 'not base64!'],
  ['without padding', (base64: string) => base64.replace(/[=]+$/, '')],
  ['wrapped across lines', wrapLines],
  [
    'in the base64url alphabet',
    (base64: string) => toBase64Url(base64).padEnd(base64.length, '='),
  ],
] as const;

describe('strict base64 decoding', () => {
  for (const input of base64Inputs) {
    for (const [description, malform] of base64Malformations) {
      const malformed = malform(input.valid);
      if (malformed === input.valid) {
        continue;
      }
      test(`rejects ${input.name} ${description}`, async () => {
        await expect(input.decrypt(input.valid)).resolves.toEqual(
          expect.any(String)
        );
        await expect(input.decrypt(malformed)).rejects.toThrow();
      });
    }
  }
});

const aesModes = [
  {
    name: 'AES-GCM',
    roundTrip: async (key: AESKey, plaintext: string) =>
      aesGcmDecrypt(key, await aesGcmEncrypt(key, plaintext)),
    decryptInvalidUtf8: () =>
      aesGcmDecrypt(aesImportKey(zeroKey), {
        ciphertext: invalidUtf8Vectors.gcmCiphertext,
        iv: invalidUtf8Vectors.gcmIv,
      }),
  },
  {
    name: 'AES-CBC',
    roundTrip: async (key: AESKey, plaintext: string) =>
      aesCbcDecrypt(key, await aesCbcEncrypt(key, plaintext)),
    decryptInvalidUtf8: () =>
      aesCbcDecrypt(
        aesImportKey(zeroKey),
        invalidUtf8Vectors.cbcIvAndCiphertext
      ),
  },
];

describe('UTF-8 plaintext', () => {
  for (const mode of aesModes) {
    test(`${mode.name} keeps a leading byte order mark`, async () => {
      expect(
        await mode.roundTrip(aesImportKey(zeroKey), byteOrderMarkPlaintext)
      ).toBe(byteOrderMarkPlaintext);
    });

    test(`${mode.name} rejects plaintext that is not valid UTF-8`, async () => {
      await expect(mode.decryptInvalidUtf8()).rejects.toThrow();
    });
  }
});

describe('inputs above the synchronous size limit', () => {
  test('round-trips large input with AES-GCM', async () => {
    const key = aesGenerateKey(32);
    const encrypted = await aesGcmEncrypt(key, largePlaintext);
    expect(await aesGcmDecrypt(key, encrypted)).toBe(largePlaintext);
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
    await expect(
      aesGcmDecrypt(key, { ciphertext: tampered, iv })
    ).rejects.toThrow();
  });
});
