import {
  afterEach,
  beforeEach,
  describe,
  expect,
  test,
} from 'react-native-harness';
import { aesDecryptFile, aesEncryptFile } from '@rocket.chat/mobile-crypto';
import { Dirs, FileSystem } from 'react-native-file-access';
import { fileVector } from './__fixtures__/crypto';

const pathFromUri = (uri: string) =>
  decodeURIComponent(uri.replace(/^file:\/\//, ''));

const emptySha256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('Native file encryption', () => {
  let directory: string;
  let inputPath: string;
  const encryptedPaths = new Set<string>();

  const encrypt = async (filePath: string) => {
    const encrypted = await aesEncryptFile(filePath);
    encryptedPaths.add(pathFromUri(encrypted.path));
    return encrypted;
  };

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

  test('returns the SHA-256 of the original file with a fresh key and IV', async () => {
    const encrypted = await encrypt(inputPath);

    expect(encrypted.sha256).toBe(fileVector.sha256);
    expect(encrypted.key).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(atob(encrypted.iv)).toHaveLength(16);
    expect(encrypted.path).toMatch(/^file:\/\//);
    expect(pathFromUri(encrypted.path)).not.toBe(inputPath);
    expect(await FileSystem.readFile(inputPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('encrypts with a different key and IV on every call', async () => {
    const first = await encrypt(inputPath);
    const second = await encrypt(inputPath);

    expect(second.key).not.toBe(first.key);
    expect(second.iv).not.toBe(first.iv);
    expect(second.sha256).toBe(first.sha256);
    expect(
      await FileSystem.readFile(pathFromUri(second.path), 'base64')
    ).not.toBe(await FileSystem.readFile(pathFromUri(first.path), 'base64'));
  });

  test('restores the original contents with the returned key, IV and SHA-256', async () => {
    const encrypted = await encrypt(inputPath);
    const encryptedPath = pathFromUri(encrypted.path);

    expect(await FileSystem.readFile(encryptedPath, 'base64')).not.toBe(
      fileVector.plaintext
    );
    const decrypted = await aesDecryptFile(
      encrypted.path,
      encrypted.key,
      encrypted.iv,
      encrypted.sha256
    );
    expect(pathFromUri(decrypted)).toBe(encryptedPath);
    expect(await FileSystem.readFile(encryptedPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('decrypts the independent NIST AES-256-CTR vector in place', async () => {
    await FileSystem.writeFile(inputPath, fileVector.ciphertext, 'base64');
    const decrypted = await aesDecryptFile(
      `file://${inputPath}`,
      fileVector.key,
      fileVector.iv,
      fileVector.sha256
    );
    expect(pathFromUri(decrypted)).toBe(inputPath);
    expect(await FileSystem.readFile(inputPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('compares the SHA-256 case-insensitively', async () => {
    await FileSystem.writeFile(inputPath, fileVector.ciphertext, 'base64');
    await aesDecryptFile(
      inputPath,
      fileVector.key,
      fileVector.iv,
      fileVector.sha256.toUpperCase()
    );
    expect(await FileSystem.readFile(inputPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('rejects a mismatched SHA-256 without leaving decrypted output', async () => {
    await FileSystem.writeFile(inputPath, fileVector.ciphertext, 'base64');

    await expect(
      aesDecryptFile(inputPath, fileVector.key, fileVector.iv, emptySha256)
    ).rejects.toThrow();

    for (const name of await FileSystem.ls(directory)) {
      expect(
        await FileSystem.readFile(`${directory}/${name}`, 'base64')
      ).not.toBe(fileVector.plaintext);
    }
  });

  test('round-trips a file larger than the native buffer from an encoded URI', async () => {
    const plaintext = '0123456789abcdef'.repeat(600);
    await FileSystem.writeFile(inputPath, plaintext);
    const encrypted = await encrypt(encodeURI(`file://${inputPath}`));

    expect(encrypted.sha256).toBe(fileVector.largeSha256);
    await aesDecryptFile(
      encrypted.path,
      encrypted.key,
      encrypted.iv,
      encrypted.sha256
    );
    expect(await FileSystem.readFile(pathFromUri(encrypted.path))).toBe(
      plaintext
    );
  });

  test('round-trips an empty file without adding padding', async () => {
    await FileSystem.writeFile(inputPath, '');
    const encrypted = await encrypt(inputPath);
    const encryptedPath = pathFromUri(encrypted.path);

    expect(encrypted.sha256).toBe(emptySha256);
    expect((await FileSystem.stat(encryptedPath)).size).toBe(0);
    await aesDecryptFile(
      encrypted.path,
      encrypted.key,
      encrypted.iv,
      encrypted.sha256
    );
    expect(await FileSystem.readFile(encryptedPath)).toBe('');
  });

  test('round-trips a file whose name is near the file system limit', async () => {
    const longInputPath = `${directory}/${'a'.repeat(226)}.bin`;
    await FileSystem.writeFile(longInputPath, fileVector.plaintext, 'base64');
    const encrypted = await encrypt(longInputPath);
    const encryptedPath = pathFromUri(encrypted.path);

    await aesDecryptFile(
      encrypted.path,
      encrypted.key,
      encrypted.iv,
      encrypted.sha256
    );
    expect(await FileSystem.readFile(encryptedPath, 'base64')).toBe(
      fileVector.plaintext
    );
  });

  test('encrypts one file concurrently to separate outputs', async () => {
    const plaintext = '0123456789abcdef'.repeat(60000);
    await FileSystem.writeFile(inputPath, plaintext);

    const [first, second] = await Promise.all([
      encrypt(inputPath),
      encrypt(inputPath),
    ]);

    expect(first.path).not.toBe(second.path);
    await Promise.all(
      [first, second].map((encrypted) =>
        aesDecryptFile(
          encrypted.path,
          encrypted.key,
          encrypted.iv,
          encrypted.sha256
        )
      )
    );
    expect(await FileSystem.readFile(pathFromUri(first.path))).toBe(plaintext);
    expect(await FileSystem.readFile(pathFromUri(second.path))).toBe(plaintext);
  });

  test('rejects a missing encryption source', async () => {
    await expect(aesEncryptFile(`${directory}/missing.bin`)).rejects.toThrow();
  });

  test('rejects a missing decryption source', async () => {
    await expect(
      aesDecryptFile(
        `${directory}/missing.bin`,
        fileVector.key,
        fileVector.iv,
        fileVector.sha256
      )
    ).rejects.toThrow();
  });
});
