import { describe, expect, test } from 'react-native-harness';
import { randomBytes, randomKey, randomUuid } from '@rocket.chat/mobile-crypto';
import { hexFromBuffer } from './__fixtures__/bytes';

describe('Native random generation', () => {
  test('generates distinct version 4 UUIDs', () => {
    const uuid = randomUuid();
    expect(uuid).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(randomUuid()).not.toBe(uuid);
  });

  for (const size of [16, 24, 32]) {
    test(`returns ${size} random key bytes as hexadecimal`, () => {
      const key = randomKey(size);
      expect(key).toHaveLength(size * 2);
      expect(key).toMatch(/^[0-9a-f]+$/i);
    });
  }

  for (const size of [0, 1, 16, 1024]) {
    test(`returns exactly ${size} random bytes`, () => {
      expect(randomBytes(size).byteLength).toBe(size);
    });
  }

  test('generates fresh keys and bytes on each call', () => {
    expect(randomKey(32)).not.toBe(randomKey(32));
    expect(hexFromBuffer(randomBytes(32))).not.toBe(
      hexFromBuffer(randomBytes(32))
    );
  });
});
