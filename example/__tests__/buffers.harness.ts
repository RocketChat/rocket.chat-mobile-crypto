import { describe, expect, test } from 'react-native-harness';
import {
  aesDecryptBuffer,
  aesEncrypt,
  aesEncryptBuffer,
  aesGcmDecryptBuffer,
  aesGcmEncrypt,
  aesGcmEncryptBuffer,
  hmac256Buffer,
  randomBytesBuffer,
  shaBuffer,
  type SHAAlgorithm,
} from '@rocket.chat/mobile-crypto';
import {
  base64FromBuffer,
  bufferFromAscii,
  bufferFromBase64,
  bufferFromHex,
  hexFromBuffer,
} from './__fixtures__/bytes';
import {
  cbcVectors,
  gcmVectors,
  hashVectors,
  hmacVectors,
} from './__fixtures__/crypto';

const zeroKey = bufferFromHex('00'.repeat(32));

describe('SHA over ArrayBuffer', () => {
  for (const vector of hashVectors) {
    test(`${vector.algorithm} returns the raw digest bytes`, async () => {
      const digest = await shaBuffer(
        bufferFromAscii('hello'),
        vector.algorithm
      );
      expect(hexFromBuffer(digest)).toBe(vector.hex);
    });
  }

  test('hashes an empty buffer', async () => {
    expect(
      base64FromBuffer(await shaBuffer(new ArrayBuffer(0), 'SHA-256'))
    ).toBe('47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
  });

  test('hashes input above the synchronous size limit', async () => {
    const digest = await shaBuffer(
      bufferFromBase64('A'.repeat(49152)),
      'SHA-256'
    );
    expect(base64FromBuffer(digest)).toBe(
      'HAJzCVOCmIMz4vK1rkh86kYHN+2b5ly62cXeU3+Vv3U='
    );
  });

  test('rejects an unsupported algorithm', async () => {
    await expect(
      shaBuffer(bufferFromAscii('hello'), 'unsupported' as SHAAlgorithm)
    ).rejects.toThrow(/"unsupported"/);
  });
});

describe('HMAC-SHA256 over ArrayBuffer', () => {
  for (const vector of hmacVectors) {
    test(vector.name, async () => {
      const authenticationCode = await hmac256Buffer(
        bufferFromHex(vector.dataHex),
        bufferFromHex(vector.keyHex)
      );
      expect(hexFromBuffer(authenticationCode)).toBe(vector.expected);
    });
  }

  test('computes an HMAC over input above the synchronous size limit', async () => {
    const authenticationCode = await hmac256Buffer(
      new ArrayBuffer(40000),
      bufferFromHex('0123456789abcdef'.repeat(4))
    );
    expect(hexFromBuffer(authenticationCode)).toBe(
      '1445721a3014318c826145c27ae9156cf8b2f0990264dcd0a4c9f825c6fa73ca'
    );
  });
});

describe('AES-CBC over ArrayBuffer', () => {
  for (const vector of cbcVectors) {
    test(`encrypts with a ${vector.bits}-bit key to a fixed ciphertext`, async () => {
      const ciphertext = await aesEncryptBuffer(
        bufferFromBase64(vector.plaintext),
        bufferFromHex(vector.keyHex),
        bufferFromHex(vector.ivHex)
      );
      expect(base64FromBuffer(ciphertext)).toBe(vector.ciphertext);
    });

    test(`decrypts a fixed ciphertext with a ${vector.bits}-bit key`, async () => {
      const plaintext = await aesDecryptBuffer(
        bufferFromBase64(vector.ciphertext),
        bufferFromHex(vector.keyHex),
        bufferFromHex(vector.ivHex)
      );
      expect(base64FromBuffer(plaintext)).toBe(vector.plaintext);
    });
  }

  test('encrypts an empty buffer to a single padding block', async () => {
    const iv = bufferFromHex('00'.repeat(16));
    const ciphertext = await aesEncryptBuffer(new ArrayBuffer(0), zeroKey, iv);
    expect(base64FromBuffer(ciphertext)).toBe('H3iP5thsMXVJaX+/DAf6Qw==');
    expect((await aesDecryptBuffer(ciphertext, zeroKey, iv)).byteLength).toBe(
      0
    );
  });

  test('matches the Base64 string API above the synchronous size limit', async () => {
    const plaintext = 'AAECAwQF'.repeat(6000);
    const keyHex = '0123456789abcdef'.repeat(4);
    const ivHex = 'fedcba9876543210fedcba9876543210';
    const ciphertext = await aesEncryptBuffer(
      bufferFromBase64(plaintext),
      bufferFromHex(keyHex),
      bufferFromHex(ivHex)
    );
    expect(base64FromBuffer(ciphertext)).toBe(
      await aesEncrypt(plaintext, keyHex, ivHex)
    );
    const decrypted = await aesDecryptBuffer(
      ciphertext,
      bufferFromHex(keyHex),
      bufferFromHex(ivHex)
    );
    expect(base64FromBuffer(decrypted)).toBe(plaintext);
  });

  test('rejects an invalid key length', async () => {
    await expect(
      aesEncryptBuffer(
        bufferFromAscii('hello'),
        bufferFromHex('00'),
        bufferFromHex('00'.repeat(16))
      )
    ).rejects.toThrow();
  });

  test('rejects an invalid IV length', async () => {
    await expect(
      aesEncryptBuffer(bufferFromAscii('hello'), zeroKey, bufferFromHex('00'))
    ).rejects.toThrow();
  });

  test('rejects ciphertext that is not a whole number of blocks', async () => {
    await expect(
      aesDecryptBuffer(
        bufferFromAscii('hello'),
        zeroKey,
        bufferFromHex('00'.repeat(16))
      )
    ).rejects.toThrow();
  });
});

describe('AES-GCM over ArrayBuffer', () => {
  for (const vector of gcmVectors) {
    test(`encrypts the ${vector.name} including the authentication tag`, async () => {
      const ciphertext = await aesGcmEncryptBuffer(
        bufferFromBase64(vector.plaintext),
        bufferFromHex(vector.keyHex),
        bufferFromHex(vector.ivHex)
      );
      expect(base64FromBuffer(ciphertext)).toBe(vector.ciphertext);
    });

    test(`decrypts the ${vector.name}`, async () => {
      const plaintext = await aesGcmDecryptBuffer(
        bufferFromBase64(vector.ciphertext),
        bufferFromHex(vector.keyHex),
        bufferFromHex(vector.ivHex)
      );
      expect(base64FromBuffer(plaintext)).toBe(vector.plaintext);
    });

    test(`rejects modified ciphertext for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecryptBuffer(
          bufferFromBase64(vector.tamperedCiphertext),
          bufferFromHex(vector.keyHex),
          bufferFromHex(vector.ivHex)
        )
      ).rejects.toThrow();
    });

    test(`rejects a modified authentication tag for the ${vector.name}`, async () => {
      await expect(
        aesGcmDecryptBuffer(
          bufferFromBase64(vector.tamperedTag),
          bufferFromHex(vector.keyHex),
          bufferFromHex(vector.ivHex)
        )
      ).rejects.toThrow();
    });
  }

  test('encrypts with a 128-bit key', async () => {
    const ciphertext = await aesGcmEncryptBuffer(
      bufferFromBase64('SGVsbG8gV29ybGQ='),
      bufferFromHex('000102030405060708090a0b0c0d0e0f'),
      bufferFromHex('fedcba9876543210fedcba98')
    );
    expect(base64FromBuffer(ciphertext)).toBe(
      'kVK5PMpu9kw8ovHb0SllMhYNRxkjCApFsH70'
    );
  });

  test('encrypts an empty buffer to only the authentication tag', async () => {
    const iv = bufferFromHex('00'.repeat(12));
    const ciphertext = await aesGcmEncryptBuffer(
      new ArrayBuffer(0),
      zeroKey,
      iv
    );
    expect(base64FromBuffer(ciphertext)).toBe('Uw+K+8dFNrmpY7TxxMtziw==');
    expect(
      (await aesGcmDecryptBuffer(ciphertext, zeroKey, iv)).byteLength
    ).toBe(0);
  });

  test('matches the Base64 string API above the synchronous size limit', async () => {
    const plaintext = 'AAECAwQF'.repeat(6000);
    const keyHex = '0123456789abcdef'.repeat(4);
    const ivHex = '00112233445566778899aabb';
    const ciphertext = await aesGcmEncryptBuffer(
      bufferFromBase64(plaintext),
      bufferFromHex(keyHex),
      bufferFromHex(ivHex)
    );
    expect(base64FromBuffer(ciphertext)).toBe(
      await aesGcmEncrypt(plaintext, keyHex, ivHex)
    );
    const decrypted = await aesGcmDecryptBuffer(
      ciphertext,
      bufferFromHex(keyHex),
      bufferFromHex(ivHex)
    );
    expect(base64FromBuffer(decrypted)).toBe(plaintext);
  });

  test('rejects input shorter than an authentication tag', async () => {
    await expect(
      aesGcmDecryptBuffer(
        bufferFromAscii('hello'),
        zeroKey,
        bufferFromHex('00'.repeat(12))
      )
    ).rejects.toThrow();
  });

  test('rejects an invalid IV length', async () => {
    await expect(
      aesGcmEncryptBuffer(
        bufferFromAscii('hello'),
        zeroKey,
        bufferFromHex('00'.repeat(16))
      )
    ).rejects.toThrow();
  });
});

describe('Random bytes as ArrayBuffer', () => {
  for (const size of [0, 1, 16, 1024]) {
    test(`returns exactly ${size} bytes`, async () => {
      expect((await randomBytesBuffer(size)).byteLength).toBe(size);
    });
  }

  test('returns fresh bytes on each call', async () => {
    expect(hexFromBuffer(await randomBytesBuffer(32))).not.toBe(
      hexFromBuffer(await randomBytesBuffer(32))
    );
  });
});
