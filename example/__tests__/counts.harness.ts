import { Platform } from 'react-native';
import { describe, expect, test } from 'react-native-harness';
import {
  aesDeriveKey,
  randomBytes,
  randomKey,
  rsaGenerateKeys,
} from '@rocket.chat/mobile-crypto';

const describeOnIOS = Platform.OS === 'ios' ? describe : describe.skip;

describeOnIOS('Counts beyond the native integer range', () => {
  for (const count of [1e19, 1e20]) {
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
        aesDeriveKey('cGFzc3dvcmQ=', 'c2FsdA==', 1, count, 'SHA256')
      ).rejects.toThrow();
    });

    test(`aesDeriveKey rejects ${count} iterations`, async () => {
      await expect(
        aesDeriveKey('cGFzc3dvcmQ=', 'c2FsdA==', count, 32, 'SHA256')
      ).rejects.toThrow();
    });
  }
});

describeOnIOS('Counts above the 32-bit integer range', () => {
  for (const count of [2 ** 31, 1e15]) {
    test(`randomBytes throws for ${count} bytes`, () => {
      expect(() => randomBytes(count)).toThrow();
    });

    test(`randomKey throws for ${count} bytes`, () => {
      expect(() => randomKey(count)).toThrow();
    });
  }
});
