import { describe, expect, test } from 'react-native-harness';
import { randomUuid, shaBase64, shaUtf8 } from '@rocket.chat/mobile-crypto';

describe('Mobile Crypto native smoke tests', () => {
  test('hashes UTF-8 through the native module', async () => {
    expect(await shaUtf8('hello', 'SHA-256')).toBe(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    );
  });

  test('hashes Base64 through the native module', async () => {
    expect(await shaBase64('aGVsbG8=', 'SHA-256')).toBe(
      'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ='
    );
  });

  test('generates a version 4 UUID through the native module', async () => {
    expect(await randomUuid()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i
    );
  });
});
