import {
  afterEach,
  beforeEach,
  describe,
  expect,
  test,
} from 'react-native-harness';
import {
  aesDecryptFile,
  aesEncryptFile,
  calculateFileChecksum,
} from '@rocket.chat/mobile-crypto';
import { Dirs, FileSystem } from 'react-native-file-access';
import { fileVector } from './__fixtures__/crypto';

const pathFromUri = (uri: string) =>
  decodeURIComponent(uri.replace(/^file:\/\//, ''));

describe('Native file encryption and checksums', () => {
  let directory: string;
  let inputPath: string;
  const encryptedPaths = new Set<string>();

  beforeEach(async () => {
    directory = `${Dirs.CacheDir}/mobile-crypto-harness-${Date.now()}`;
    await FileSystem.mkdir(directory);
    inputPath = `${directory}/payload 🔐.bin`;
    await FileSystem.writeFile(inputPath, fileVector.plaintext, 'base64');
  });

  afterEach(async () => {
    for (const path of encryptedPaths) {
      if (await FileSystem.exists(path)) {
        await FileSystem.unlink(path);
      }
    }
    encryptedPaths.clear();
    if (await FileSystem.exists(directory)) {
      await FileSystem.unlink(directory);
    }
  });

  test('calculates the known SHA-256 checksum from a file path', async () => {
    expect(await calculateFileChecksum(inputPath)).toBe(fileVector.checksum);
  });

  test('calculates a checksum from a file URI', async () => {
    expect(await calculateFileChecksum(`file://${inputPath}`)).toBe(
      fileVector.checksum
    );
  });

  test('decodes spaces and Unicode in file URIs', async () => {
    expect(await calculateFileChecksum(encodeURI(`file://${inputPath}`))).toBe(
      fileVector.checksum
    );
  });

  test('hashes a file larger than the 4096-byte native read buffer', async () => {
    await FileSystem.writeFile(inputPath, '0123456789abcdef'.repeat(600));
    expect(await calculateFileChecksum(inputPath)).toBe(
      fileVector.largeChecksum
    );
  });

  test('calculates the SHA-256 checksum of an empty file', async () => {
    await FileSystem.writeFile(inputPath, '');
    expect(await calculateFileChecksum(inputPath)).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  test('encrypts to the NIST AES-256-CTR ciphertext and preserves the source', async () => {
    const encrypted = await aesEncryptFile(
      inputPath,
      fileVector.key,
      fileVector.iv
    );
    const encryptedPath = pathFromUri(encrypted);
    encryptedPaths.add(encryptedPath);

    expect(encrypted).toMatch(/^file:\/\//);
    expect(encryptedPath).not.toBe(inputPath);
    expect(await FileSystem.readFile(encryptedPath, 'base64')).toBe(
      fileVector.ciphertext
    );
    expect(await FileSystem.readFile(inputPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('decrypts the independent NIST vector in place', async () => {
    await FileSystem.writeFile(inputPath, fileVector.ciphertext, 'base64');
    const decrypted = await aesDecryptFile(
      `file://${inputPath}`,
      fileVector.key,
      fileVector.iv
    );
    expect(pathFromUri(decrypted)).toBe(inputPath);
    expect(await FileSystem.readFile(inputPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('round-trips a file larger than the native buffer', async () => {
    const plaintext = '0123456789abcdef'.repeat(600);
    await FileSystem.writeFile(inputPath, plaintext);
    const encrypted = await aesEncryptFile(
      encodeURI(`file://${inputPath}`),
      fileVector.key,
      fileVector.iv
    );
    const encryptedPath = pathFromUri(encrypted);
    encryptedPaths.add(encryptedPath);
    const decrypted = await aesDecryptFile(
      encrypted,
      fileVector.key,
      fileVector.iv
    );

    expect(pathFromUri(decrypted)).toBe(encryptedPath);
    expect(await FileSystem.readFile(encryptedPath)).toBe(plaintext);
    expect(await calculateFileChecksum(encryptedPath)).toBe(
      fileVector.largeChecksum
    );
  });

  test('round-trips an empty file without adding padding', async () => {
    await FileSystem.writeFile(inputPath, '');
    const encrypted = await aesEncryptFile(
      inputPath,
      fileVector.key,
      fileVector.iv
    );
    const encryptedPath = pathFromUri(encrypted);
    encryptedPaths.add(encryptedPath);
    expect((await FileSystem.stat(encryptedPath)).size).toBe(0);
    await aesDecryptFile(encrypted, fileVector.key, fileVector.iv);
    expect(await FileSystem.readFile(encryptedPath)).toBe('');
  });

  test('encrypts one file concurrently with different keys to separate outputs', async () => {
    const otherKey = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
    const otherIv = 'AAECAwQFBgcICQoLDA0ODw==';
    const plaintext = '0123456789abcdef'.repeat(60000);
    await FileSystem.writeFile(inputPath, plaintext);

    const [encrypted, otherEncrypted] = await Promise.all([
      aesEncryptFile(inputPath, fileVector.key, fileVector.iv),
      aesEncryptFile(inputPath, otherKey, otherIv),
    ]);
    const encryptedPath = pathFromUri(encrypted);
    const otherEncryptedPath = pathFromUri(otherEncrypted);
    encryptedPaths.add(encryptedPath);
    encryptedPaths.add(otherEncryptedPath);

    expect(encryptedPath).not.toBe(otherEncryptedPath);
    await aesDecryptFile(encrypted, fileVector.key, fileVector.iv);
    await aesDecryptFile(otherEncrypted, otherKey, otherIv);
    expect(await FileSystem.readFile(encryptedPath)).toBe(plaintext);
    expect(await FileSystem.readFile(otherEncryptedPath)).toBe(plaintext);
  });

  test('rejects a missing file when calculating a checksum', async () => {
    await expect(
      calculateFileChecksum(`${directory}/missing.bin`)
    ).rejects.toThrow();
  });

  test('rejects a missing encryption source', async () => {
    await expect(
      aesEncryptFile(`${directory}/missing.bin`, fileVector.key, fileVector.iv)
    ).rejects.toThrow();
  });

  test('rejects a missing decryption source', async () => {
    await expect(
      aesDecryptFile(`${directory}/missing.bin`, fileVector.key, fileVector.iv)
    ).rejects.toThrow();
  });
});
