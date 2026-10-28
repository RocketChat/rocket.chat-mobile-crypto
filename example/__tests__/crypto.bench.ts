import { describe, test } from 'react-native-harness';
import {
  aesDecrypt,
  aesDecryptBuffer,
  aesEncrypt,
  aesEncryptBuffer,
  aesGcmDecrypt,
  aesGcmDecryptBuffer,
  aesGcmEncrypt,
  aesGcmEncryptBuffer,
  hmac256,
  hmac256Buffer,
  pbkdf2Hash,
  randomBytes,
  randomBytesBuffer,
  randomUuid,
  rsaDecrypt,
  rsaEncrypt,
  rsaExportKey,
  rsaGenerateKeys,
  rsaImportKey,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  rsaSign,
  rsaVerify,
  shaBase64,
  shaBuffer,
  shaUtf8,
} from '@rocket.chat/mobile-crypto';
import { Dirs, FileSystem } from 'react-native-file-access';
import {
  bufferFromAscii,
  bufferFromBase64,
  bufferFromHex,
} from './__fixtures__/bytes';

const keyHex = '0123456789abcdef'.repeat(4);
const cbcIvHex = 'fedcba9876543210fedcba9876543210';
const gcmIvHex = '00112233445566778899aabb';

const base64OfSize = (byteCount: number) =>
  'AAAA'
    .repeat(Math.ceil(byteCount / 3))
    .slice(0, Math.ceil(byteCount / 3) * 4);

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
    const small = base64OfSize(32);
    const oneKilobyte = base64OfSize(1024);
    const oneMegabyte = base64OfSize(1024 * 1024);
    const cbcCiphertext = (await aesEncrypt(oneKilobyte, keyHex, cbcIvHex))!;
    const gcmCiphertext = (await aesGcmEncrypt(oneKilobyte, keyHex, gcmIvHex))!;
    const keyPair = await rsaGenerateKeys(2048);
    const rsaCiphertext = await rsaEncrypt('hello', keyPair.public);
    const signature = await rsaSign('hello', keyPair.private, 'SHA256');
    const privateJwk = await rsaExportKey(keyPair.private);

    await measure('randomUuid', 1000, () => randomUuid());
    await measure('randomBytes(16)', 1000, () => randomBytes(16));
    await measure('shaUtf8 SHA-256 short', 1000, () =>
      shaUtf8('hello', 'SHA-256')
    );
    await measure('shaBase64 SHA-256 32B', 1000, () =>
      shaBase64(small, 'SHA-256')
    );
    await measure('hmac256 short', 1000, () => hmac256('68656c6c6f', keyHex));
    await measure('aesEncrypt CBC 1KB', 1000, () =>
      aesEncrypt(oneKilobyte, keyHex, cbcIvHex)
    );
    await measure('aesDecrypt CBC 1KB', 1000, () =>
      aesDecrypt(cbcCiphertext, keyHex, cbcIvHex)
    );
    await measure('aesGcmEncrypt 1KB', 1000, () =>
      aesGcmEncrypt(oneKilobyte, keyHex, gcmIvHex)
    );
    await measure('aesGcmDecrypt 1KB', 1000, () =>
      aesGcmDecrypt(gcmCiphertext, keyHex, gcmIvHex)
    );
    await measure('aesEncrypt CBC 1MB', 30, () =>
      aesEncrypt(oneMegabyte, keyHex, cbcIvHex)
    );
    await measure('aesGcmEncrypt 1MB', 30, () =>
      aesGcmEncrypt(oneMegabyte, keyHex, gcmIvHex)
    );
    await measure('pbkdf2 SHA256 1000 iterations', 100, () =>
      pbkdf2Hash(small, small, 1000, 32, 'SHA256')
    );
    await measure('rsaEncrypt 2048', 300, () =>
      rsaEncrypt('hello', keyPair.public)
    );
    await measure('rsaDecrypt 2048', 100, () =>
      rsaDecrypt(rsaCiphertext, keyPair.private)
    );
    await measure('rsaSign SHA256 2048', 100, () =>
      rsaSign('hello', keyPair.private, 'SHA256')
    );
    await measure('rsaVerify SHA256 2048', 300, () =>
      rsaVerify(signature, 'hello', keyPair.public, 'SHA256')
    );
    await measure('rsaExportKey private', 300, () =>
      rsaExportKey(keyPair.private)
    );
    await measure('rsaImportKey private', 300, () => rsaImportKey(privateJwk));
    await measure('rsaGenerateKeys 2048', 10, () => rsaGenerateKeys(2048));
    const keyBuffer = bufferFromHex(keyHex);
    const cbcIvBuffer = bufferFromHex(cbcIvHex);
    const gcmIvBuffer = bufferFromHex(gcmIvHex);
    const smallBuffer = bufferFromBase64(small);
    const oneKilobyteBuffer = bufferFromBase64(oneKilobyte);
    const oneMegabyteBuffer = bufferFromBase64(oneMegabyte);
    const helloBuffer = bufferFromAscii('hello');
    const cbcCiphertextBuffer = await aesEncryptBuffer(
      oneKilobyteBuffer,
      keyBuffer,
      cbcIvBuffer
    );
    const gcmCiphertextBuffer = await aesGcmEncryptBuffer(
      oneKilobyteBuffer,
      keyBuffer,
      gcmIvBuffer
    );
    const privateKey = await rsaImportPrivateKey(keyPair.private);
    const publicKey = await rsaImportPublicKey(keyPair.public);
    const rsaCiphertextBuffer = bufferFromBase64(rsaCiphertext);
    const signatureBuffer = bufferFromBase64(signature);

    await measure('randomBytesBuffer(16)', 1000, () => randomBytesBuffer(16));
    await measure('shaBuffer SHA-256 32B', 1000, () =>
      shaBuffer(smallBuffer, 'SHA-256')
    );
    await measure('hmac256Buffer short', 1000, () =>
      hmac256Buffer(helloBuffer, keyBuffer)
    );
    await measure('aesEncryptBuffer CBC 1KB', 1000, () =>
      aesEncryptBuffer(oneKilobyteBuffer, keyBuffer, cbcIvBuffer)
    );
    await measure('aesDecryptBuffer CBC 1KB', 1000, () =>
      aesDecryptBuffer(cbcCiphertextBuffer, keyBuffer, cbcIvBuffer)
    );
    await measure('aesGcmEncryptBuffer 1KB', 1000, () =>
      aesGcmEncryptBuffer(oneKilobyteBuffer, keyBuffer, gcmIvBuffer)
    );
    await measure('aesGcmDecryptBuffer 1KB', 1000, () =>
      aesGcmDecryptBuffer(gcmCiphertextBuffer, keyBuffer, gcmIvBuffer)
    );
    await measure('aesEncryptBuffer CBC 1MB', 30, () =>
      aesEncryptBuffer(oneMegabyteBuffer, keyBuffer, cbcIvBuffer)
    );
    await measure('aesGcmEncryptBuffer 1MB', 30, () =>
      aesGcmEncryptBuffer(oneMegabyteBuffer, keyBuffer, gcmIvBuffer)
    );
    await measure('rsaImportPrivateKey 2048', 300, () =>
      rsaImportPrivateKey(keyPair.private)
    );
    await measure('RSAPublicKey.encrypt 2048', 300, async () =>
      publicKey.encrypt(helloBuffer)
    );
    await measure('RSAPrivateKey.decrypt 2048', 100, () =>
      privateKey.decrypt(rsaCiphertextBuffer)
    );
    await measure('RSAPrivateKey.sign SHA256 2048', 100, () =>
      privateKey.sign(helloBuffer, 'SHA256')
    );
    await measure('RSAPublicKey.verify SHA256 2048', 300, async () =>
      publicKey.verify(signatureBuffer, helloBuffer, 'SHA256')
    );
    await measureConcurrent('shaUtf8 x200 concurrent', 200, 20, () =>
      shaUtf8('hello', 'SHA-256')
    );

    await FileSystem.writeFile(
      `${Dirs.CacheDir}/bench-results.txt`,
      results.join('\n')
    );
  });
});
