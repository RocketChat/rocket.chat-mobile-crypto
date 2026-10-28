import { Platform } from 'react-native';
import { describe, expect, test } from 'react-native-harness';
import {
  getRandomValues,
  pbkdf2Hash,
  randomBytes,
  randomBytesBuffer,
  randomKey,
  rsaGenerateKeys,
} from '@rocket.chat/mobile-crypto';

const describeOnIOS = Platform.OS === 'ios' ? describe : describe.skip;

describeOnIOS('Counts beyond the native integer range', () => {
  for (const count of [1e19, 1e20]) {
    test(`randomKey rejects ${count}`, async () => {
      await expect(randomKey(count)).rejects.toThrow();
    });

    test(`randomBytes rejects ${count}`, async () => {
      await expect(randomBytes(count)).rejects.toThrow();
    });

    test(`randomBytesBuffer rejects ${count}`, async () => {
      await expect(randomBytesBuffer(count)).rejects.toThrow();
    });

    test(`getRandomValues rejects ${count}`, async () => {
      await expect(getRandomValues(count)).rejects.toThrow();
    });

    test(`rsaGenerateKeys rejects a ${count}-bit key size`, async () => {
      await expect(rsaGenerateKeys(count)).rejects.toThrow();
    });

    test(`pbkdf2Hash rejects a ${count}-byte key length`, async () => {
      await expect(
        pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 1, count, 'SHA256')
      ).rejects.toThrow();
    });

    test(`pbkdf2Hash rejects ${count} iterations`, async () => {
      await expect(
        pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', count, 32, 'SHA256')
      ).rejects.toThrow();
    });
  }
});
