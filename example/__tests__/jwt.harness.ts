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
  SUPPORTED_VERSIONS_PUBLIC_JWK,
  UNSIGNED_JWT,
} from './__fixtures__/jwt';
import cloudInfo from './__fixtures__/supported-versions/cloud-info.json';
import serverInfo from './__fixtures__/supported-versions/server-info.json';
import serverPayload from './__fixtures__/supported-versions/server-payload.json';

const serverJwt = serverInfo.supportedVersions.signed;

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

  test('returns the supported versions a server sends in /api/info', async () => {
    expect(
      JSON.parse(await rsaVerifyJwt(supportedVersionsPublicKey, serverJwt))
    ).toEqual(serverPayload);
  });

  test('returns the supported versions the cloud also sends unsigned', async () => {
    const { signed, ...unsigned } = cloudInfo;
    expect(
      JSON.parse(await rsaVerifyJwt(supportedVersionsPublicKey, signed))
    ).toEqual(unsigned);
  });

  test('returns a UTF-8 payload unchanged', async () => {
    expect(await rsaVerifyJwt(fixedPublicKey, FIXED_KEY_JWT)).toBe(
      FIXED_KEY_JWT_PAYLOAD
    );
  });

  test('rejects a JWT signed by another key', async () => {
    await expect(rsaVerifyJwt(fixedPublicKey, serverJwt)).rejects.toThrow();
  });

  test('rejects a payload the signature does not cover', async () => {
    const signed = segmentsOf(FIXED_KEY_JWT);
    const other = segmentsOf(serverJwt);
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
    const { header, payload, signature } = segmentsOf(serverJwt);
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
