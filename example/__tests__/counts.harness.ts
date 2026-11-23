import { describe, expect, test } from 'react-native-harness';
import {
  aesDeriveKey,
  randomBytes,
  randomKey,
  rsaGenerateKeys,
} from '@rocket.chat/mobile-crypto';
import { passwordBase64, saltBase64 } from './__fixtures__/crypto';

const invalidCounts = [-1, NaN, 2 ** 31, 1e15, 1e19, 1e20];

describe('Counts outside 0 to 2^31 - 1', () => {
  for (const count of invalidCounts) {
    test(`randomKey throws for ${count}`, () => {
      expect(() => randomKey(count)).toThrow();
    });

    test(`randomBytes throws for ${count}`, () => {
      expect(() => randomBytes(count)).toThrow();
    });

    test(`rsaGenerateKeys rejects a ${count}-bit key size`, async () => {
      await expect(rsaGenerateKeys(count)).rejects.toThrow();
    });

    test(`aesDeriveKey rejects a ${count}-byte key length`, async () => {
      await expect(
        aesDeriveKey(passwordBase64, saltBase64, {
          iterations: 1,
          byteLength: count,
          hash: 'SHA256',
        })
      ).rejects.toThrow();
    });
  }

  for (const iterations of [0, ...invalidCounts]) {
    test(`aesDeriveKey rejects ${iterations} iterations`, async () => {
      await expect(
        aesDeriveKey(passwordBase64, saltBase64, {
          iterations,
          byteLength: 32,
          hash: 'SHA256',
        })
      ).rejects.toThrow();
    });
  }
});
