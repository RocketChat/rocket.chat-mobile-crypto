import { describe, expect, test } from 'react-native-harness';
import {
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
} from '@rocket.chat/mobile-crypto';
import {
  RSA_FIXED_PRIVATE_JWK,
  RSA_FIXED_PUBLIC_JWK,
  RSA_FIXED_SIGNATURE,
  RSA_FIXED_SIGN_MESSAGE,
} from '../fixtures/rsa';
import { bufferFromAscii, bufferFromBase64 } from './__fixtures__/bytes';

const privateFields = ['d', 'p', 'q', 'dp', 'dq', 'qi'];
const { n, e } = JSON.parse(RSA_FIXED_PUBLIC_JWK);

describe('RSA keys as JWK', () => {
  test('exports an imported private key as the identical JWK', async () => {
    const privateKey = await rsaImportPrivateKey(RSA_FIXED_PRIVATE_JWK);
    expect(privateKey.exportJwk()).toBe(RSA_FIXED_PRIVATE_JWK);
  });

  test('exports an imported public key as the identical JWK', async () => {
    const publicKey = await rsaImportPublicKey(RSA_FIXED_PUBLIC_JWK);
    expect(publicKey.exportJwk()).toBe(RSA_FIXED_PUBLIC_JWK);
  });

  test('imports a public key from a private JWK, ignoring private fields', async () => {
    const publicKey = await rsaImportPublicKey(RSA_FIXED_PRIVATE_JWK);
    expect(publicKey.exportJwk()).toBe(RSA_FIXED_PUBLIC_JWK);
  });

  test('imports a minimal public JWK with only the modulus and exponent', async () => {
    const publicKey = await rsaImportPublicKey(
      JSON.stringify({ kty: 'RSA', n, e })
    );
    expect(publicKey.exportJwk()).toBe(RSA_FIXED_PUBLIC_JWK);
    expect(
      await publicKey.verify(
        bufferFromBase64(RSA_FIXED_SIGNATURE),
        bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
        'SHA256'
      )
    ).toBe(true);
  });

  test('generates a 2048-bit key pair by default', async () => {
    const { publicKey, privateKey } = await rsaGenerateKeys();
    const publicJwk = JSON.parse(publicKey.exportJwk());
    const privateJwk = JSON.parse(privateKey.exportJwk());

    expect(publicJwk.n).toHaveLength(342);
    expect(publicJwk.e).toBe('AQAB');
    expect(privateJwk.n).toBe(publicJwk.n);
    for (const field of privateFields) {
      expect(field in publicJwk).toBe(false);
      expect(privateJwk[field]).toMatch(/^[A-Za-z0-9_-]+$/);
    }
  });

  test('generates a fresh key pair on every call', async () => {
    const first = await rsaGenerateKeys(2048);
    const second = await rsaGenerateKeys(2048);
    expect(second.publicKey.exportJwk()).not.toBe(first.publicKey.exportJwk());
  });

  test('round-trips generated keys through JWK export and import', async () => {
    const keys = await rsaGenerateKeys(2048);
    const privateJwk = keys.privateKey.exportJwk();
    const publicJwk = keys.publicKey.exportJwk();
    const privateKey = await rsaImportPrivateKey(privateJwk);
    const publicKey = await rsaImportPublicKey(publicJwk);

    expect(privateKey.exportJwk()).toBe(privateJwk);
    expect(publicKey.exportJwk()).toBe(publicJwk);
    expect(
      await privateKey.decrypt(await keys.publicKey.encrypt('generated'))
    ).toBe('generated');
    expect(
      await keys.privateKey.decrypt(await publicKey.encrypt('imported'))
    ).toBe('imported');
  });

  for (const [description, jwk] of [
    ['text that is not JSON', 'not JSON'],
    ['an empty object', '{}'],
    ['a JWK without a modulus', JSON.stringify({ kty: 'RSA', e })],
    [
      'a modulus that is not base64url',
      JSON.stringify({ kty: 'RSA', n: '!', e }),
    ],
  ]) {
    test(`rejects ${description} as a public key`, async () => {
      await expect(rsaImportPublicKey(jwk!)).rejects.toThrow();
    });

    test(`rejects ${description} as a private key`, async () => {
      await expect(rsaImportPrivateKey(jwk!)).rejects.toThrow();
    });
  }

  test('rejects a public JWK as a private key', async () => {
    await expect(rsaImportPrivateKey(RSA_FIXED_PUBLIC_JWK)).rejects.toThrow();
  });
});
