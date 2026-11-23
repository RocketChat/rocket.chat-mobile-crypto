import { describe, expect, test } from 'react-native-harness';
import { randomUuid, sha } from '@rocket.chat/mobile-crypto';
import { bufferFromAscii, hexFromBuffer } from './__fixtures__/bytes';
import { sha256OfHelloHex } from './__fixtures__/crypto';

describe('Mobile Crypto native smoke tests', () => {
  test('hashes bytes through the native module', async () => {
    expect(hexFromBuffer(await sha(bufferFromAscii('hello'), 'SHA-256'))).toBe(
      sha256OfHelloHex
    );
  });

  test('generates a version 4 UUID through the native module', () => {
    expect(randomUuid()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });
});
