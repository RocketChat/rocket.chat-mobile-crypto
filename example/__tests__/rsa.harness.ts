import { beforeAll, describe, expect, test } from 'react-native-harness';
import {
  rsaDecrypt,
  rsaDecrypt64,
  rsaEncrypt,
  rsaEncrypt64,
  rsaExportKey,
  rsaGenerateKeys,
  rsaImportKey,
  rsaPemToJwk,
  rsaSign,
  rsaSign64,
  rsaVerify,
  rsaVerify64,
  type JWK,
  type RSAHashAlgorithm,
} from '@rocket.chat/mobile-crypto';
import {
  RSA_FIXED_JWK,
  RSA_FIXED_OAEP_CIPHERTEXT_B64,
  RSA_FIXED_PLAINTEXT,
  RSA_FIXED_PRIVATE_KEY,
  RSA_FIXED_PUBLIC_KEY,
  RSA_FIXED_SIGNATURE_B64,
  RSA_FIXED_SIGN_MESSAGE,
} from '../fixtures/rsa';

describe('RSA encryption and signatures', () => {
  let generatedKeys: { public: string; private: string };

  beforeAll(async () => {
    generatedKeys = await rsaGenerateKeys(2048);
  });

  test('generates a usable 2048-bit PEM key pair', async () => {
    expect(generatedKeys.public).toMatch(/-----BEGIN (RSA )?PUBLIC KEY-----/);
    expect(generatedKeys.private).toMatch(/-----BEGIN (RSA )?PRIVATE KEY-----/);
    const jwk = await rsaExportKey(generatedKeys.public);
    expect(jwk.n).toHaveLength(342);
    expect(jwk.e).toBe('AQAB');
  });

  test('defaults to a 2048-bit key pair when no size is provided', async () => {
    const keys = await rsaGenerateKeys();
    const jwk = await rsaExportKey(keys.public);
    expect(jwk.n).toHaveLength(342);
    expect(keys.public).not.toBe(generatedKeys.public);
  });

  test('round-trips UTF-8 text with generated keys', async () => {
    const message = 'Rocket.Chat 🔐 — olá';
    const ciphertext = await rsaEncrypt(message, generatedKeys.public);
    expect(ciphertext).not.toBe(message);
    expect(await rsaDecrypt(ciphertext, generatedKeys.private)).toBe(message);
  });

  test('round-trips binary Base64 input without UTF-8 conversion', async () => {
    const plaintext = 'AAF/gP7/';
    const ciphertext = await rsaEncrypt64(plaintext, generatedKeys.public);
    expect(await rsaDecrypt64(ciphertext, generatedKeys.private)).toBe(
      plaintext
    );
  });

  test('uses the same plaintext bytes for UTF-8 and Base64 encryption APIs', async () => {
    const ciphertext = await rsaEncrypt64('aGVsbG8=', generatedKeys.public);
    expect(await rsaDecrypt(ciphertext, generatedKeys.private)).toBe('hello');
    const utf8Ciphertext = await rsaEncrypt('hello', generatedKeys.public);
    expect(await rsaDecrypt64(utf8Ciphertext, generatedKeys.private)).toBe(
      'aGVsbG8='
    );
  });

  test('decrypts the independent OAEP-SHA256 known-answer vector', async () => {
    expect(
      await rsaDecrypt(RSA_FIXED_OAEP_CIPHERTEXT_B64, RSA_FIXED_PRIVATE_KEY)
    ).toBe(RSA_FIXED_PLAINTEXT);
  });

  test('decrypts the fixed OAEP ciphertext to Base64 bytes', async () => {
    expect(
      await rsaDecrypt64(RSA_FIXED_OAEP_CIPHERTEXT_B64, RSA_FIXED_PRIVATE_KEY)
    ).toBe('SGVsbG8gUlNBIGZpeGVkIHZlY3RvciE=');
  });

  test('signs to the exact PKCS#1 v1.5 SHA-256 known answer', async () => {
    expect(
      await rsaSign(RSA_FIXED_SIGN_MESSAGE, RSA_FIXED_PRIVATE_KEY, 'SHA256')
    ).toBe(RSA_FIXED_SIGNATURE_B64);
  });

  test('verifies the independent PKCS#1 v1.5 SHA-256 signature', async () => {
    expect(
      await rsaVerify(
        RSA_FIXED_SIGNATURE_B64,
        RSA_FIXED_SIGN_MESSAGE,
        RSA_FIXED_PUBLIC_KEY,
        'SHA256'
      )
    ).toBe(true);
  });

  test('rejects a signature for a changed message', async () => {
    expect(
      await rsaVerify(
        RSA_FIXED_SIGNATURE_B64,
        `${RSA_FIXED_SIGN_MESSAGE} modified`,
        RSA_FIXED_PUBLIC_KEY,
        'SHA256'
      )
    ).toBe(false);
  });

  test('signs Base64-decoded bytes to the same fixed signature', async () => {
    expect(
      await rsaSign64(
        'SGVsbG8gUlNBIHNpZ25hdHVyZSBmaXhlZCB2ZWN0b3Ih',
        RSA_FIXED_PRIVATE_KEY,
        'SHA256'
      )
    ).toBe(RSA_FIXED_SIGNATURE_B64);
  });

  test('rejects an unsupported signature hash', async () => {
    await expect(
      rsaSign(
        RSA_FIXED_SIGN_MESSAGE,
        RSA_FIXED_PRIVATE_KEY,
        'unsupported' as RSAHashAlgorithm
      )
    ).rejects.toThrow(/"unsupported"/);
  });

  test('rejects an unsupported signature hash for Base64-decoded bytes', async () => {
    await expect(
      rsaSign64(
        'SGVsbG8gUlNBIHNpZ25hdHVyZSBmaXhlZCB2ZWN0b3Ih',
        RSA_FIXED_PRIVATE_KEY,
        'unsupported' as RSAHashAlgorithm
      )
    ).rejects.toThrow(/"unsupported"/);
  });

  test('verifies the fixed signature against Base64-decoded bytes', async () => {
    expect(
      await rsaVerify64(
        RSA_FIXED_SIGNATURE_B64,
        'SGVsbG8gUlNBIHNpZ25hdHVyZSBmaXhlZCB2ZWN0b3Ih',
        RSA_FIXED_PUBLIC_KEY,
        'SHA256'
      )
    ).toBe(true);
  });

  test('rejects a signature for changed Base64-decoded bytes', async () => {
    expect(
      await rsaVerify64(
        RSA_FIXED_SIGNATURE_B64,
        'bW9kaWZpZWQ=',
        RSA_FIXED_PUBLIC_KEY,
        'SHA256'
      )
    ).toBe(false);
  });

  test('signs and verifies non-UTF-8 binary data', async () => {
    const message = 'AAF/gP7/';
    const signature = await rsaSign64(message, generatedKeys.private, 'SHA256');
    expect(
      await rsaVerify64(signature, message, generatedKeys.public, 'SHA256')
    ).toBe(true);
  });

  for (const algorithm of [
    'SHA1',
    'SHA224',
    'SHA256',
    'SHA384',
    'SHA512',
  ] as const) {
    test(`signs and verifies using ${algorithm}`, async () => {
      const signature = await rsaSign(
        'message',
        generatedKeys.private,
        algorithm
      );
      expect(
        await rsaVerify(signature, 'message', generatedKeys.public, algorithm)
      ).toBe(true);
    });
  }

  test('signs and verifies when the optional hash is omitted', async () => {
    const signature = await rsaSign('message', generatedKeys.private);
    expect(await rsaVerify(signature, 'message', generatedKeys.public)).toBe(
      true
    );
  });

  test('rejects a ciphertext encrypted for a different private key', async () => {
    await expect(
      rsaDecrypt(RSA_FIXED_OAEP_CIPHERTEXT_B64, generatedKeys.private)
    ).rejects.toThrow();
  });

  test('rejects plaintext larger than the OAEP block can hold', async () => {
    await expect(
      rsaEncrypt('x'.repeat(256), generatedKeys.public)
    ).rejects.toThrow();
  });

  test('rejects an invalid encryption key', async () => {
    await expect(rsaEncrypt('hello', 'invalid PEM')).rejects.toThrow();
  });
});

describe('RSA JWK conversions', () => {
  test('exports the fixed public key modulus and exponent', async () => {
    expect(await rsaExportKey(RSA_FIXED_PUBLIC_KEY)).toMatchObject(
      RSA_FIXED_JWK
    );
  });

  test('supports the rsaPemToJwk public alias', async () => {
    expect(await rsaPemToJwk(RSA_FIXED_PUBLIC_KEY)).toMatchObject(
      RSA_FIXED_JWK
    );
  });

  test('imports a public JWK and preserves its key material', async () => {
    const pem = await rsaImportKey(RSA_FIXED_JWK);
    expect(pem).toContain('-----BEGIN RSA PUBLIC KEY-----');
    expect(await rsaExportKey(pem)).toMatchObject(RSA_FIXED_JWK);
    const encrypted = await rsaEncrypt('imported key', pem);
    expect(await rsaDecrypt(encrypted, RSA_FIXED_PRIVATE_KEY)).toBe(
      'imported key'
    );
  });

  test('exports every private RSA component', async () => {
    const jwk = await rsaExportKey(RSA_FIXED_PRIVATE_KEY);
    expect(jwk).toMatchObject(RSA_FIXED_JWK);
    for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi'] as const) {
      expect(jwk[field]).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  test('round-trips all private JWK components through PEM', async () => {
    const original = await rsaExportKey(RSA_FIXED_PRIVATE_KEY);
    const pem = await rsaImportKey(original);
    expect(pem).toContain('-----BEGIN RSA PRIVATE KEY-----');
    expect(await rsaExportKey(pem)).toEqual(original);
  });

  test('rejects a JWK without key components', async () => {
    await expect(rsaImportKey({} as JWK)).rejects.toThrow();
  });

  test('rejects an invalid PEM export', async () => {
    await expect(rsaExportKey('invalid PEM')).rejects.toThrow();
  });
});
