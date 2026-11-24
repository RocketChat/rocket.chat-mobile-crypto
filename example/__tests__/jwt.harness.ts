import { beforeAll, describe, expect, test } from 'react-native-harness';
import {
  rsaImportPublicKey,
  rsaVerifyJwt,
  type RSAPublicKey,
} from '@rocket.chat/mobile-crypto';
import { RSA_FIXED_PUBLIC_JWK } from './__fixtures__/rsa';
import {
  FIXED_KEY_JWT,
  FIXED_KEY_JWT_PAYLOAD,
  FIXED_KEY_RS512_HEADER_JWT,
  SUPPORTED_VERSIONS_JWT,
  SUPPORTED_VERSIONS_PAYLOAD_FIELDS,
  SUPPORTED_VERSIONS_PUBLIC_JWK,
  UNSIGNED_JWT,
} from './__fixtures__/jwt';

const segmentsOf = (jwt: string) => {
  const [header, payload, signature] = jwt.split('.') as [
    string,
    string,
    string,
  ];
  return { header, payload, signature };
};

describe('RS256 JWT verification', () => {
  let fixedPublicKey: RSAPublicKey;
  let supportedVersionsPublicKey: RSAPublicKey;

  beforeAll(async () => {
    fixedPublicKey = await rsaImportPublicKey(RSA_FIXED_PUBLIC_JWK);
    supportedVersionsPublicKey = await rsaImportPublicKey(
      SUPPORTED_VERSIONS_PUBLIC_JWK
    );
  });

  test('returns the payload of a Rocket.Chat signed supported versions JWT', async () => {
    const payload = JSON.parse(
      await rsaVerifyJwt(supportedVersionsPublicKey, SUPPORTED_VERSIONS_JWT)
    );
    expect({
      timestamp: payload.timestamp,
      enforcementStartDate: payload.enforcementStartDate,
      versionsCount: payload.versions.length,
      firstVersion: payload.versions[0].version,
    }).toEqual(SUPPORTED_VERSIONS_PAYLOAD_FIELDS);
  });

  test('returns a UTF-8 payload unchanged', async () => {
    expect(await rsaVerifyJwt(fixedPublicKey, FIXED_KEY_JWT)).toBe(
      FIXED_KEY_JWT_PAYLOAD
    );
  });

  test('rejects a JWT signed by another key', async () => {
    await expect(
      rsaVerifyJwt(fixedPublicKey, SUPPORTED_VERSIONS_JWT)
    ).rejects.toThrow();
  });

  test('rejects a payload the signature does not cover', async () => {
    const signed = segmentsOf(FIXED_KEY_JWT);
    const other = segmentsOf(SUPPORTED_VERSIONS_JWT);
    const tampered = `${signed.header}.${other.payload}.${signed.signature}`;
    await expect(rsaVerifyJwt(fixedPublicKey, tampered)).rejects.toThrow();
  });

  test('rejects an alg other than RS256 even when the RS256 signature matches', async () => {
    await expect(
      rsaVerifyJwt(fixedPublicKey, FIXED_KEY_RS512_HEADER_JWT)
    ).rejects.toThrow();
  });

  test('rejects an unsigned JWT', async () => {
    await expect(rsaVerifyJwt(fixedPublicKey, UNSIGNED_JWT)).rejects.toThrow();
  });

  test('rejects a JWT without exactly three segments', async () => {
    const { header, payload, signature } = segmentsOf(FIXED_KEY_JWT);
    await expect(
      rsaVerifyJwt(fixedPublicKey, `${header}.${payload}`)
    ).rejects.toThrow();
    await expect(
      rsaVerifyJwt(fixedPublicKey, `${header}.${payload}.${signature}.`)
    ).rejects.toThrow();
  });

  test('rejects a signature in the standard base64 alphabet', async () => {
    const { header, payload, signature } = segmentsOf(SUPPORTED_VERSIONS_JWT);
    const standardSignature = signature.replace(/-/g, '+').replace(/_/g, '/');
    expect(standardSignature).not.toBe(signature);
    await expect(
      rsaVerifyJwt(
        supportedVersionsPublicKey,
        `${header}.${payload}.${standardSignature}`
      )
    ).rejects.toThrow();
  });

  test('rejects a header that is not JSON', async () => {
    const { payload, signature } = segmentsOf(FIXED_KEY_JWT);
    await expect(
      rsaVerifyJwt(fixedPublicKey, `bm90IGpzb24.${payload}.${signature}`)
    ).rejects.toThrow();
  });
});
