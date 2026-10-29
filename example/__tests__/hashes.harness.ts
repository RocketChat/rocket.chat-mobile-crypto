import { describe, expect, test } from 'react-native-harness';
import {
  hmac256,
  randomBytes,
  sha,
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
  binaryHashVector,
  hashVectors,
  hmacVectors,
  unicodeVector,
} from './__fixtures__/crypto';

const unsupportedAlgorithm = 'unsupported' as SHAAlgorithm;
const largeInput = () => bufferFromBase64('A'.repeat(49152));

describe('SHA known answers', () => {
  for (const vector of hashVectors) {
    test(`${vector.algorithm} returns the raw digest bytes`, async () => {
      const digest = await sha(bufferFromAscii('hello'), vector.algorithm);
      expect(hexFromBuffer(digest)).toBe(vector.hex);
      expect(base64FromBuffer(digest)).toBe(vector.base64);
    });
  }

  test('hashes an empty buffer', async () => {
    expect(base64FromBuffer(await sha(new ArrayBuffer(0), 'SHA-256'))).toBe(
      '47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='
    );
  });

  test('hashes UTF-8 bytes of emoji and accented characters', async () => {
    const digest = await sha(bufferFromBase64(unicodeVector.base64), 'SHA-256');
    expect(hexFromBuffer(digest)).toBe(unicodeVector.hex);
    expect(base64FromBuffer(digest)).toBe(unicodeVector.digestBase64);
  });

  test('hashes binary bytes that are not valid UTF-8', async () => {
    const digest = await sha(
      bufferFromBase64(binaryHashVector.base64),
      'SHA-256'
    );
    expect(base64FromBuffer(digest)).toBe(binaryHashVector.digestBase64);
  });

  test('rejects an unsupported algorithm', async () => {
    await expect(
      sha(bufferFromAscii('hello'), unsupportedAlgorithm)
    ).rejects.toThrow(/"unsupported"/);
  });
});

describe('HMAC-SHA256 known answers', () => {
  for (const vector of hmacVectors) {
    test(vector.name, async () => {
      const authenticationCode = await hmac256(
        bufferFromHex(vector.dataHex),
        bufferFromHex(vector.keyHex)
      );
      expect(hexFromBuffer(authenticationCode)).toBe(vector.expected);
    });
  }
});

describe('inputs above the synchronous size limit', () => {
  test('hashes large input', async () => {
    expect(base64FromBuffer(await sha(largeInput(), 'SHA-256'))).toBe(
      'HAJzCVOCmIMz4vK1rkh86kYHN+2b5ly62cXeU3+Vv3U='
    );
  });

  test('rejects an unsupported algorithm for large input', async () => {
    await expect(sha(largeInput(), unsupportedAlgorithm)).rejects.toThrow(
      /"unsupported"/
    );
  });

  test('computes an HMAC over large input', async () => {
    const authenticationCode = await hmac256(
      new ArrayBuffer(40000),
      bufferFromHex('0123456789abcdef'.repeat(4))
    );
    expect(hexFromBuffer(authenticationCode)).toBe(
      '1445721a3014318c826145c27ae9156cf8b2f0990264dcd0a4c9f825c6fa73ca'
    );
  });

  test('ignores changes to the input made while hashing', async () => {
    const input = randomBytes(16 * 1024 * 1024);
    const untouchedInput = input.slice(0);

    const pendingDigest = sha(input, 'SHA-256');
    new Uint8Array(input).fill(0);

    expect(hexFromBuffer(await pendingDigest)).toBe(
      hexFromBuffer(await sha(untouchedInput, 'SHA-256'))
    );
  });
});
