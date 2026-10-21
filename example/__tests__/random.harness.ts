import { describe, expect, test } from 'react-native-harness';
import {
  getRandomValues,
  randomBytes,
  randomKey,
  randomUuid,
} from '@rocket.chat/mobile-crypto';

describe('Native random generation', () => {
  test('generates distinct version 4 UUIDs', async () => {
    const uuid = await randomUuid();
    expect(uuid).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
    expect(await randomUuid()).not.toBe(uuid);
  });

  for (const size of [16, 24, 32]) {
    test(`returns ${size} random key bytes as hexadecimal`, async () => {
      const key = await randomKey(size);
      expect(key).toHaveLength(size * 2);
      expect(key).toMatch(/^[0-9a-f]+$/i);
    });
  }

  for (const size of [1, 2, 3, 8, 32]) {
    test(`returns ${size} random bytes as padded Base64`, async () => {
      const bytes = await randomBytes(size);
      expect(bytes).toHaveLength(4 * Math.ceil(size / 3));
      expect(bytes).toMatch(/^[A-Za-z0-9+/]+={0,2}$/);
      const padding = size % 3 === 0 ? 0 : 3 - (size % 3);
      expect(bytes.length - bytes.replace(/[=]+$/, '').length).toBe(padding);
    });
  }

  for (const length of [1, 10, 64]) {
    test(`returns exactly ${length} alphanumeric characters`, async () => {
      const value = await getRandomValues(length);
      expect(value).toHaveLength(length);
      expect(value).toMatch(/^[A-Za-z0-9]+$/);
    });
  }

  test('generates fresh keys, bytes, and alphanumeric values on each call', async () => {
    expect(await randomKey(32)).not.toBe(await randomKey(32));
    expect(await randomBytes(32)).not.toBe(await randomBytes(32));
    expect(await getRandomValues(64)).not.toBe(await getRandomValues(64));
  });
});
