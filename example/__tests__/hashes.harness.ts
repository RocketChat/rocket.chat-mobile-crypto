import { describe, expect, test } from 'react-native-harness';
import {
  hmac256,
  pbkdf2Hash,
  shaBase64,
  shaUtf8,
  type PBKDF2HashAlgorithm,
  type SHAAlgorithm,
} from '@rocket.chat/mobile-crypto';
import {
  binaryHashVector,
  binaryPbkdf2Vector,
  hashVectors,
  hmacVectors,
  pbkdf2Vectors,
  unicodeVector,
} from './__fixtures__/crypto';

describe('SHA known answers', () => {
  for (const vector of hashVectors) {
    test(`${vector.algorithm} returns a hexadecimal UTF-8 digest`, async () => {
      expect(await shaUtf8('hello', vector.algorithm)).toBe(vector.hex);
    });

    test(`${vector.algorithm} returns a Base64 digest of decoded bytes`, async () => {
      expect(await shaBase64('aGVsbG8=', vector.algorithm)).toBe(vector.base64);
    });
  }

  test('hashes an empty UTF-8 string', async () => {
    expect(await shaUtf8('', 'SHA-256')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  test('hashes empty Base64 input', async () => {
    expect(await shaBase64('', 'SHA-256')).toBe(
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
    );
  });

  test('preserves emoji and accented UTF-8 characters', async () => {
    expect(await shaUtf8(unicodeVector.text, 'SHA-256')).toBe(
      unicodeVector.hex
    );
    expect(await shaBase64(unicodeVector.base64, 'SHA-256')).toBe(
      unicodeVector.digestBase64
    );
  });

  test('hashes binary bytes that are not valid UTF-8', async () => {
    expect(await shaBase64(binaryHashVector.base64, 'SHA-256')).toBe(
      binaryHashVector.digestBase64
    );
  });

  const unsupportedAlgorithm = 'unsupported' as SHAAlgorithm;

  test('rejects an unsupported UTF-8 hash algorithm', async () => {
    await expect(shaUtf8('hello', unsupportedAlgorithm)).rejects.toThrow(
      /"unsupported"/
    );
  });

  test('rejects an unsupported Base64 hash algorithm', async () => {
    await expect(shaBase64('aGVsbG8=', unsupportedAlgorithm)).rejects.toThrow(
      /"unsupported"/
    );
  });

  test('rejects malformed Base64 input', async () => {
    await expect(shaBase64('a===', 'SHA-256')).rejects.toThrow();
  });
});

describe('PBKDF2 known answers', () => {
  for (const vector of pbkdf2Vectors) {
    test(`derives ${vector.keyLength} bytes with ${vector.algorithm}`, async () => {
      expect(
        await pbkdf2Hash(
          'cGFzc3dvcmQ=',
          'c2FsdA==',
          1000,
          vector.keyLength,
          vector.algorithm
        )
      ).toBe(vector.expected);
    });
  }

  test('matches the single-iteration RFC 6070 SHA-1 vector', async () => {
    expect(await pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 1, 20, 'SHA1')).toBe(
      'DGDID5YfDnHzqbUkr2ASBi/gN6Y='
    );
  });

  test('preserves null bytes in the decoded password and salt', async () => {
    expect(
      await pbkdf2Hash(
        binaryPbkdf2Vector.password,
        binaryPbkdf2Vector.salt,
        4096,
        16,
        'SHA256'
      )
    ).toBe(binaryPbkdf2Vector.expected);
  });

  test('rejects an unsupported hash algorithm', async () => {
    await expect(
      pbkdf2Hash(
        'cGFzc3dvcmQ=',
        'c2FsdA==',
        1000,
        32,
        'unsupported' as PBKDF2HashAlgorithm
      )
    ).rejects.toThrow(/"unsupported"/);
  });
});

describe('HMAC-SHA256 known answers', () => {
  for (const vector of hmacVectors) {
    test(vector.name, async () => {
      expect(await hmac256(vector.dataHex, vector.keyHex)).toBe(
        vector.expected
      );
    });
  }
});

describe('inputs above the synchronous size limit', () => {
  test('hashes large Base64 input', async () => {
    expect(await shaBase64('A'.repeat(49152), 'SHA-256')).toBe(
      'HAJzCVOCmIMz4vK1rkh86kYHN+2b5ly62cXeU3+Vv3U='
    );
  });

  test('hashes a large UTF-8 string', async () => {
    expect(await shaUtf8('a'.repeat(40000), 'SHA-256')).toBe(
      '72a2f8d2643328a2e03dcb1b66fdc6610b95ba3019d88d8849ce060d0be634ce'
    );
  });

  test('computes an HMAC over large input', async () => {
    expect(
      await hmac256('00'.repeat(20000), '0123456789abcdef'.repeat(4))
    ).toBe('6271447fab534de65abf22d387b9d75d635231deb617eec3e8775a1b9d275564');
  });

  test('rejects an unsupported Base64 hash algorithm', async () => {
    await expect(
      shaBase64('A'.repeat(49152), 'unsupported' as SHAAlgorithm)
    ).rejects.toThrow(/"unsupported"/);
  });

  test('rejects an unsupported UTF-8 hash algorithm', async () => {
    await expect(
      shaUtf8('a'.repeat(40000), 'unsupported' as SHAAlgorithm)
    ).rejects.toThrow(/"unsupported"/);
  });
});
