import { describe, test } from 'react-native-harness';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  aesDeriveKey,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesImportKey,
  hmac256,
  randomBytes,
  randomUuid,
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  sha,
} from '@rocket.chat/mobile-crypto';
import { Dirs, FileSystem } from 'react-native-file-access';
import { bufferFromAscii } from './__fixtures__/bytes';

const keyBase64Url = 'ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8';

const textOfSize = (characterCount: number) => 'a'.repeat(characterCount);

const results: string[] = [];

const report = (line: string) => {
  results.push(line);
  console.log(line);
};

const percentile = (sorted: number[], fraction: number) =>
  sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))]!;

const measure = async (
  name: string,
  iterations: number,
  operation: () => Promise<unknown>
) => {
  const warmupCount = Math.min(20, Math.ceil(iterations / 5));
  for (let index = 0; index < warmupCount; index++) {
    await operation();
  }
  const durations: number[] = [];
  for (let index = 0; index < iterations; index++) {
    const start = performance.now();
    await operation();
    durations.push(performance.now() - start);
  }
  durations.sort((left, right) => left - right);
  const total = durations.reduce((sum, duration) => sum + duration, 0);
  report(
    `BENCH ${JSON.stringify({
      name,
      iterations,
      medianMs: percentile(durations, 0.5),
      p95Ms: percentile(durations, 0.95),
      meanMs: total / iterations,
    })}`
  );
};

const measureConcurrent = async (
  name: string,
  batchSize: number,
  rounds: number,
  operation: () => Promise<unknown>
) => {
  await Promise.all(Array.from({ length: batchSize }, operation));
  const durations: number[] = [];
  for (let round = 0; round < rounds; round++) {
    const start = performance.now();
    await Promise.all(Array.from({ length: batchSize }, operation));
    durations.push(performance.now() - start);
  }
  durations.sort((left, right) => left - right);
  report(
    `BENCH ${JSON.stringify({
      name,
      iterations: batchSize * rounds,
      medianMs: percentile(durations, 0.5),
      p95Ms: percentile(durations, 0.95),
      meanMs: durations.reduce((sum, duration) => sum + duration, 0) / rounds,
    })}`
  );
};

describe('benchmark', () => {
  test('crypto call latency', async () => {
    const key = aesImportKey(keyBase64Url);
    const oneKilobyte = textOfSize(1024);
    const oneMegabyte = textOfSize(1024 * 1024);
    const smallBuffer = randomBytes(32);
    const helloBuffer = bufferFromAscii('hello');
    const keyBuffer = randomBytes(32);
    const gcmCiphertext = await aesGcmEncrypt(key, oneKilobyte);
    const cbcCiphertext = await aesCbcEncrypt(key, oneKilobyte);
    const { publicKey, privateKey } = await rsaGenerateKeys(2048);
    const privateJwk = privateKey.exportJwk();
    const publicJwk = publicKey.exportJwk();
    const rsaCiphertext = await publicKey.encrypt('hello');
    const signature = await privateKey.sign(helloBuffer, 'SHA256');

    await measure('randomUuid', 1000, async () => randomUuid());
    await measure('randomBytes(16)', 1000, async () => randomBytes(16));
    await measure('sha SHA-256 32B', 1000, () => sha(smallBuffer, 'SHA-256'));
    await measure('hmac256 short', 1000, () => hmac256(helloBuffer, keyBuffer));
    await measure('aesImportKey', 1000, async () => aesImportKey(keyBase64Url));
    await measure('aesGcmEncrypt 1KB', 1000, () =>
      aesGcmEncrypt(key, oneKilobyte)
    );
    await measure('aesGcmDecrypt 1KB', 1000, () =>
      aesGcmDecrypt(key, gcmCiphertext.ciphertext, gcmCiphertext.iv)
    );
    await measure('aesCbcEncrypt 1KB', 1000, () =>
      aesCbcEncrypt(key, oneKilobyte)
    );
    await measure('aesCbcDecrypt 1KB', 1000, () =>
      aesCbcDecrypt(key, cbcCiphertext)
    );
    await measure('aesGcmEncrypt 1MB', 30, () =>
      aesGcmEncrypt(key, oneMegabyte)
    );
    await measure('aesCbcEncrypt 1MB', 30, () =>
      aesCbcEncrypt(key, oneMegabyte)
    );
    await measure('aesDeriveKey SHA256 1000 iterations', 100, () =>
      aesDeriveKey('cGFzc3dvcmQ=', 'c2FsdA==', 1000, 32, 'SHA256')
    );
    await measure('rsaImportPrivateKey 2048', 300, () =>
      rsaImportPrivateKey(privateJwk)
    );
    await measure('rsaImportPublicKey 2048', 300, () =>
      rsaImportPublicKey(publicJwk)
    );
    await measure('RSAPrivateKey.exportJwk 2048', 300, async () =>
      privateKey.exportJwk()
    );
    await measure('RSAPublicKey.encrypt 2048', 300, async () =>
      publicKey.encrypt('hello')
    );
    await measure('RSAPrivateKey.decrypt 2048', 100, () =>
      privateKey.decrypt(rsaCiphertext)
    );
    await measure('RSAPrivateKey.sign SHA256 2048', 100, () =>
      privateKey.sign(helloBuffer, 'SHA256')
    );
    await measure('RSAPublicKey.verify SHA256 2048', 300, async () =>
      publicKey.verify(signature, helloBuffer, 'SHA256')
    );
    await measure('rsaGenerateKeys 2048', 10, () => rsaGenerateKeys(2048));
    await measureConcurrent('sha x200 concurrent', 200, 20, () =>
      sha(helloBuffer, 'SHA-256')
    );

    await FileSystem.writeFile(
      `${Dirs.CacheDir}/bench-results.txt`,
      results.join('\n')
    );
  });
});
