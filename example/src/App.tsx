import { useState, useEffect } from 'react';
import {
  Text,
  View,
  StyleSheet,
  ScrollView,
  Button,
  Platform,
} from 'react-native';
import {
  shaBase64,
  shaUtf8,
  pbkdf2Hash,
  hmac256,
  aesEncrypt,
  aesDecrypt,
  aesGcmEncrypt,
  aesGcmDecrypt,
  randomUuid,
  randomKey,
  randomBytes,
  rsaGenerateKeys,
  rsaEncrypt,
  rsaDecrypt,
  rsaSign,
  rsaVerify,
  getRandomValues,
  rsaImportKey,
  rsaExportKey,
  type JWK,
} from '@rocket.chat/mobile-crypto';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

// ---------------------------------------------------------------------------
// Fixed RSA known-answer vectors (KAT)
//
// One 2048-bit keypair generated once with openssl; the same key material is
// expressed in two encodings because the native layers parse different PEM
// forms: Android (KeyFactory) needs PKCS#8 private + X.509/SPKI public, iOS
// (SecKeyCreateWithData) needs raw PKCS#1 ("RSA PRIVATE/PUBLIC KEY"). Both
// encodings share the same modulus, so the SAME ciphertext and SAME signature
// below decrypt/verify on either platform.
//
// Params: OAEP-SHA256 / MGF1-SHA256 for encryption; PKCS#1 v1.5 + SHA-256 for
// signatures (deterministic, so the signature is pinned for exact equality).
// Generation commands are recorded in the NATIVE-1235 report.
// ---------------------------------------------------------------------------

const RSA_FIXED_PRIVATE_PKCS8 = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCnKUeAYbH9k0PF
omxXMiq927jIcLQn8FF0pTA3fVnORn69S5ALVIUoVsI60z2aYElP+Xfdoe4kCnfJ
GWFb+6pHf3MowwQJQbRDvFByRnrayop8RC002bY4jxoJiD9ITEtb6SMteNZAaSuu
aiZxnqd2wcYiZQEWhF/niYNQbwYCQfPcEIxDX+vA6EQOs6asMm0dW14qtBC9xMhY
1eSAVIXEaxKxMqedlkDHKReLblLARebCYQdCsCcRcG+o/n33ygM7PX8cWe71Tb1F
UGqPAGBWKLgndY/NLkewrGE+tsHuaTiDDtipaLR5dfc5RNbKqVCdOHrff16hu0TK
rz9AALO1AgMBAAECggEAC0pX+H1gwsJQGQiz7Z3HUkSFchBesrXiIpFHtO/EAZE0
XT+9zm4aglN90fBToFoxiXPNm0wlJA0K8yvCLi7M3QBoPFATtTZZYRvWiSlmgeGd
QfBu5ztvOdm8hflMYOs6Sc5w4FDhk78mwqSLzS/MmtJSuh79WFJ/kclxc5zUGJHU
tj7LJN39XVoo7QHNsR+jirmEjKNhSfcua7GhkZZC/u21jIvse9cwJBGQHazTWesP
XM6n37pqVMRqR8uQ+q+ZfesfiJZENSVkKYkd3yRIHRFkgN+sKSEgKcyuE71Yj6wD
jA9HZQVSTdiiqsrwUFeo3fEib9fBgPXMRBc51X49XwKBgQDmSL6MH2V22zB3S+ED
8Zb/CSIOK+rjD/wAVWFMcGgKSVtC9qi8wY6RKDBrNW1P5Bph1rqvmMwxErn/q8GH
e9WxmFMjPrg50ojANl0kJ+/pY3D9QmCdDXaL5YY0GSSQgGtw9WyqbFrrfEp27BFB
onWEmQUZ1b68D1g8AcW2mle1wwKBgQC51AG76qhZO6+hFkrNWz/et7c6pUrnN7gL
ipSW82SKN521DXk7Dyx/hIAyARuVimYHzi67dklIIwv4b2kLhWBtp9qD5z5cijpY
AXzlK2Zyw43avubLjJrxyROA1iQlvwpnSP7GUsIBIrUWGDDjIRcg2i9AP3CSzLkx
cr2kezTBJwKBgCmHlu2YP+kmcGAjTAo1CIEn+X9Kxkp6uHyq6Sgq4WhxgEbcSuP3
mClvcQP0l6kfvu5EFljSmoiDEw4bwIQZfhlQGjYx+nFbGZRoeXWqyiZx64+Q5/GK
2wUxuHkuy5xPvJCbgiRd9Cuht6AoxJfsn3rxSa02EfbCYaw4uZpLzWOXAoGAZWtH
5v+TEeB5YjmAacO7gBpUbjV4Q+ktEV946Um9PZJNCFtqJsmJR69RJ/lizKLUPL5S
0w0jwbMe/WAQvLD2h+JsaED00BzA6vck6w5cw5Xm/dPisoTyq7NKaa513AP/8Y7t
PeA88dG3c2+QfuW4cb2ivDXjgrso98vfpL15dVECgYBp9FX8KFcau2XJQAcn/58U
SlrkRatVddO681C1HjV5XoopNf2HzRU/YE6UqOlBSH/IKEZ3EhEsrLl7VtnNsvJJ
N7PFLSQF6tZjgNBft/DuA5gmuU2B8OjTM173b/B9DJQhoQ3NYvYfgobCrwfCRoZ5
tFzdyeChLZyQfOZF7PzCAQ==
-----END PRIVATE KEY-----`;

const RSA_FIXED_PUBLIC_SPKI = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApylHgGGx/ZNDxaJsVzIq
vdu4yHC0J/BRdKUwN31ZzkZ+vUuQC1SFKFbCOtM9mmBJT/l33aHuJAp3yRlhW/uq
R39zKMMECUG0Q7xQckZ62sqKfEQtNNm2OI8aCYg/SExLW+kjLXjWQGkrrmomcZ6n
dsHGImUBFoRf54mDUG8GAkHz3BCMQ1/rwOhEDrOmrDJtHVteKrQQvcTIWNXkgFSF
xGsSsTKnnZZAxykXi25SwEXmwmEHQrAnEXBvqP5998oDOz1/HFnu9U29RVBqjwBg
Vii4J3WPzS5HsKxhPrbB7mk4gw7YqWi0eXX3OUTWyqlQnTh6339eobtEyq8/QACz
tQIDAQAB
-----END PUBLIC KEY-----`;

const RSA_FIXED_PRIVATE_PKCS1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEApylHgGGx/ZNDxaJsVzIqvdu4yHC0J/BRdKUwN31ZzkZ+vUuQ
C1SFKFbCOtM9mmBJT/l33aHuJAp3yRlhW/uqR39zKMMECUG0Q7xQckZ62sqKfEQt
NNm2OI8aCYg/SExLW+kjLXjWQGkrrmomcZ6ndsHGImUBFoRf54mDUG8GAkHz3BCM
Q1/rwOhEDrOmrDJtHVteKrQQvcTIWNXkgFSFxGsSsTKnnZZAxykXi25SwEXmwmEH
QrAnEXBvqP5998oDOz1/HFnu9U29RVBqjwBgVii4J3WPzS5HsKxhPrbB7mk4gw7Y
qWi0eXX3OUTWyqlQnTh6339eobtEyq8/QACztQIDAQABAoIBAAtKV/h9YMLCUBkI
s+2dx1JEhXIQXrK14iKRR7TvxAGRNF0/vc5uGoJTfdHwU6BaMYlzzZtMJSQNCvMr
wi4uzN0AaDxQE7U2WWEb1okpZoHhnUHwbuc7bznZvIX5TGDrOknOcOBQ4ZO/JsKk
i80vzJrSUroe/VhSf5HJcXOc1BiR1LY+yyTd/V1aKO0BzbEfo4q5hIyjYUn3Lmux
oZGWQv7ttYyL7HvXMCQRkB2s01nrD1zOp9+6alTEakfLkPqvmX3rH4iWRDUlZCmJ
Hd8kSB0RZIDfrCkhICnMrhO9WI+sA4wPR2UFUk3YoqrK8FBXqN3xIm/XwYD1zEQX
OdV+PV8CgYEA5ki+jB9ldtswd0vhA/GW/wkiDivq4w/8AFVhTHBoCklbQvaovMGO
kSgwazVtT+QaYda6r5jMMRK5/6vBh3vVsZhTIz64OdKIwDZdJCfv6WNw/UJgnQ12
i+WGNBkkkIBrcPVsqmxa63xKduwRQaJ1hJkFGdW+vA9YPAHFtppXtcMCgYEAudQB
u+qoWTuvoRZKzVs/3re3OqVK5ze4C4qUlvNkijedtQ15Ow8sf4SAMgEblYpmB84u
u3ZJSCML+G9pC4Vgbafag+c+XIo6WAF85StmcsON2r7my4ya8ckTgNYkJb8KZ0j+
xlLCASK1Fhgw4yEXINovQD9wksy5MXK9pHs0wScCgYAph5btmD/pJnBgI0wKNQiB
J/l/SsZKerh8qukoKuFocYBG3Erj95gpb3ED9JepH77uRBZY0pqIgxMOG8CEGX4Z
UBo2MfpxWxmUaHl1qsomceuPkOfxitsFMbh5LsucT7yQm4IkXfQrobegKMSX7J96
8UmtNhH2wmGsOLmaS81jlwKBgGVrR+b/kxHgeWI5gGnDu4AaVG41eEPpLRFfeOlJ
vT2STQhbaibJiUevUSf5Ysyi1Dy+UtMNI8GzHv1gELyw9ofibGhA9NAcwOr3JOsO
XMOV5v3T4rKE8quzSmmuddwD//GO7T3gPPHRt3NvkH7luHG9orw144K7KPfL36S9
eXVRAoGAafRV/ChXGrtlyUAHJ/+fFEpa5EWrVXXTuvNQtR41eV6KKTX9h80VP2BO
lKjpQUh/yChGdxIRLKy5e1bZzbLySTezxS0kBerWY4DQX7fw7gOYJrlNgfDo0zNe
92/wfQyUIaENzWL2H4KGwq8HwkaGebRc3cngoS2ckHzmRez8wgE=
-----END RSA PRIVATE KEY-----`;

const RSA_FIXED_PUBLIC_PKCS1 = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEApylHgGGx/ZNDxaJsVzIqvdu4yHC0J/BRdKUwN31ZzkZ+vUuQC1SF
KFbCOtM9mmBJT/l33aHuJAp3yRlhW/uqR39zKMMECUG0Q7xQckZ62sqKfEQtNNm2
OI8aCYg/SExLW+kjLXjWQGkrrmomcZ6ndsHGImUBFoRf54mDUG8GAkHz3BCMQ1/r
wOhEDrOmrDJtHVteKrQQvcTIWNXkgFSFxGsSsTKnnZZAxykXi25SwEXmwmEHQrAn
EXBvqP5998oDOz1/HFnu9U29RVBqjwBgVii4J3WPzS5HsKxhPrbB7mk4gw7YqWi0
eXX3OUTWyqlQnTh6339eobtEyq8/QACztQIDAQAB
-----END RSA PUBLIC KEY-----`;

// Platform-branched key material (same modulus, encoding the native layer parses).
const RSA_FIXED_PRIVATE_KEY = Platform.select({
  ios: RSA_FIXED_PRIVATE_PKCS1,
  default: RSA_FIXED_PRIVATE_PKCS8,
});
const RSA_FIXED_PUBLIC_KEY = Platform.select({
  ios: RSA_FIXED_PUBLIC_PKCS1,
  default: RSA_FIXED_PUBLIC_SPKI,
});

const RSA_FIXED_PLAINTEXT = 'Hello RSA fixed vector!';
const RSA_FIXED_SIGN_MESSAGE = 'Hello RSA signature fixed vector!';

// OAEP-SHA256/MGF1-SHA256 ciphertext of RSA_FIXED_PLAINTEXT (base64).
const RSA_FIXED_OAEP_CIPHERTEXT_B64 =
  'i08WpnMEqWx2wLI85uir06hnBpUgMM/zO1y/XWgue/tIz6Nb28MFTBuDPMshhpoz' +
  'WM8uhYhfcnYAPwAmKiN5Mp8uFYKO2f0kpSs7GYopR7D284NX+ar67LLxXgRdDhXb' +
  'mo5msDqSCmrhN1MTMVI2GGr/RStdRyODmHiRAqw0+6OM1431GvNm2MOPh+imTEwgu' +
  'Si/tqiWvRDP4n9A9Kk+tBrhJLfHjMMY5ig1NuvzV35KM96hw6R6VpcWVX3cNbnxW' +
  'bytRsygp7oswA83PZtAvLH8wIAqLDBHoQTHNg0TNWbfR6WxoSecTh7W/4iB8XUeJ' +
  '4mwT/KgnRz6yIVQ0iLgnw==';

// PKCS#1 v1.5 SHA-256 signature of RSA_FIXED_SIGN_MESSAGE (base64, deterministic).
const RSA_FIXED_SIGNATURE_B64 =
  'lySFWshaUVSbp+U1m+dq1wW4VuHBX1jE30L4gJywhjvfB4jMf2WrTMdYbdMnvXgj' +
  'E4kGJ3Lkcu5C6isOUHZMMIYDdL8DRW6GNTWj5ChwQXLQ6TV0NYkOmGqrEkWxztk6' +
  '/lu/SWogTuKiq7iVpbAtjfyFTY6GWeyqIw0AOoFfDKQSezeF6ubRkKEDLc42v+pX' +
  'FTRxWMJTMXX6+Xz5PiDV+ApXO4ExDtsgW1gqwNUTeY7y/A+2XIxllZTVj4LB7twa' +
  'K5DirX0GIvUD5VomiHiy8dGGQc3m8FZa6c5te78FC7JCe4GRLHKNdH1hzEggTH3S' +
  'MDHrlJnNqFiE2bQenbHKEg==';

// JWK of the same key (base64url components) — pins export/import answers.
const RSA_FIXED_JWK: JWK = {
  kty: 'RSA',
  n:
    'pylHgGGx_ZNDxaJsVzIqvdu4yHC0J_BRdKUwN31ZzkZ-vUuQC1SFKFbCOtM9mmBJ' +
    'T_l33aHuJAp3yRlhW_uqR39zKMMECUG0Q7xQckZ62sqKfEQtNNm2OI8aCYg_SExL' +
    'W-kjLXjWQGkrrmomcZ6ndsHGImUBFoRf54mDUG8GAkHz3BCMQ1_rwOhEDrOmrDJt' +
    'HVteKrQQvcTIWNXkgFSFxGsSsTKnnZZAxykXi25SwEXmwmEHQrAnEXBvqP5998oD' +
    'Oz1_HFnu9U29RVBqjwBgVii4J3WPzS5HsKxhPrbB7mk4gw7YqWi0eXX3OUTWyqlQ' +
    'nTh6339eobtEyq8_QACztQ',
  e: 'AQAB',
};

export default function App() {
  const [results, setResults] = useState<{ [key: string]: string }>({});
  const [loading, setLoading] = useState<{ [key: string]: boolean }>({});

  const runCryptoTests = async () => {
    const tests = [
      {
        key: 'utf8-sha256',
        label: 'SHA-256 UTF-8 ("hello")',
        fn: () => shaUtf8('hello', 'SHA-256'),
        expected:
          '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
      },
      {
        key: 'utf8-sha1',
        label: 'SHA-1 UTF-8 ("hello")',
        fn: () => shaUtf8('hello', 'SHA-1'),
        expected: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
      },
      {
        key: 'base64-sha256',
        label: 'SHA-256 Base64 ("aGVsbG8=")',
        fn: () => shaBase64('aGVsbG8=', 'SHA-256'), // "hello" in base64
        expected: 'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=',
      },
      {
        key: 'utf8-sha512',
        label: 'SHA-512 UTF-8 ("test")',
        fn: () => shaUtf8('test', 'SHA-512'),
        expected:
          'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff',
      },
      {
        key: 'pbkdf2-sha256',
        label: 'PBKDF2-SHA256 ("cGFzc3dvcmQ=", "c2FsdA==", 1000, 32)',
        fn: () => pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 1000, 32, 'SHA256'), // "password", "salt"
        expected: 'YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM=',
      },
      {
        key: 'pbkdf2-sha1',
        label: 'PBKDF2-SHA1 ("cGFzc3dvcmQ=", "c2FsdA==", 1000, 20)',
        fn: () => pbkdf2Hash('cGFzc3dvcmQ=', 'c2FsdA==', 1000, 20, 'SHA1'), // "password", "salt"
        expected: 'boi+i61+rp2eEKoGEiQDT+1I0D8=',
      },
      {
        key: 'hmac256-test1',
        label: 'HMAC-SHA256 (data="48656c6c6f", key="6b6579")', // "Hello", "key"
        fn: () => hmac256('48656c6c6f', '6b6579'),
        expected:
          'c70b9f4d665bd62974afc83582de810e72a41a58db82c538a9d734c9266d321e',
      },
      {
        key: 'hmac256-test2',
        label: 'HMAC-SHA256 (data="74657374", key="6b6579")', // "test", "key"
        fn: () => hmac256('74657374', '6b6579'),
        expected:
          '02afb56304902c656fcb737cdd03de6205bb6d401da2812efd9b2d36a08af159',
      },
      {
        key: 'aes-encrypt-test',
        label: 'AES Encrypt ("SGVsbG8gV29ybGQ=", key, iv)', // "Hello World" in base64
        fn: async () => {
          const encrypted = await aesEncrypt(
            'SGVsbG8gV29ybGQ=', // "Hello World" base64
            '0123456789abcdef0123456789abcdef', // 128-bit key in hex
            'fedcba9876543210fedcba9876543210' // 128-bit IV in hex
          );
          return encrypted || 'null';
        },
        expected: 'encrypted', // We'll verify it's not null and not the original
      },
      {
        key: 'aes-roundtrip-test',
        label: 'AES Encrypt->Decrypt Roundtrip',
        fn: async () => {
          const original = 'SGVsbG8gV29ybGQ='; // "Hello World" base64
          const key = '0123456789abcdef0123456789abcdef';
          const iv = 'fedcba9876543210fedcba9876543210';

          const encrypted = await aesEncrypt(original, key, iv);
          if (!encrypted) return 'encrypt failed';

          const decrypted = await aesDecrypt(encrypted, key, iv);
          return decrypted === original ? 'PASS' : `FAIL: got ${decrypted}`;
        },
        expected: 'PASS',
      },
      {
        key: 'aes-gcm-encrypt-test',
        label: 'AES-256-GCM Encrypt ("SGVsbG8gV29ybGQ=", key, iv)', // "Hello World" in base64
        fn: async () => {
          const encrypted = await aesGcmEncrypt(
            'SGVsbG8gV29ybGQ=', // "Hello World" base64
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', // 256-bit key in hex
            'fedcba9876543210fedcba98' // 96-bit IV in hex (12 bytes)
          );
          return encrypted || 'null';
        },
        expected: 'encrypted', // We'll verify it's not null and not the original
      },
      {
        key: 'aes-gcm-roundtrip-test',
        label: 'AES-256-GCM Encrypt->Decrypt Roundtrip',
        fn: async () => {
          const original = 'SGVsbG8gV29ybGQ='; // "Hello World" base64
          const key =
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // 256-bit key
          const iv = 'fedcba9876543210fedcba98'; // 96-bit IV

          const encrypted = await aesGcmEncrypt(original, key, iv);
          if (!encrypted) return 'encrypt failed';

          const decrypted = await aesGcmDecrypt(encrypted, key, iv);
          return decrypted === original ? 'PASS' : `FAIL: got ${decrypted}`;
        },
        expected: 'PASS',
      },
      {
        key: 'aes-gcm-auth-test',
        label: 'AES-256-GCM Authentication Test (wrong key)',
        fn: async () => {
          const original = 'SGVsbG8gV29ybGQ='; // "Hello World" base64
          const key =
            '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
          const wrongKey =
            '1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'; // Different key
          const iv = 'fedcba9876543210fedcba98';

          const encrypted = await aesGcmEncrypt(original, key, iv);
          if (!encrypted) return 'encrypt failed';

          // Try to decrypt with wrong key - should fail authentication
          const decrypted = await aesGcmDecrypt(encrypted, wrongKey, iv);
          return decrypted === null
            ? 'PASS (auth failed as expected)'
            : `FAIL: got ${decrypted}`;
        },
        expected: 'PASS (auth failed as expected)',
      },
      {
        key: 'random-uuid-test',
        label: 'Random UUID Generation',
        fn: async () => {
          const uuid = await randomUuid();
          // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
          const uuidRegex =
            /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
          return uuidRegex.test(uuid) ? 'VALID UUID' : `INVALID: ${uuid}`;
        },
        expected: 'VALID UUID',
      },
      {
        key: 'random-key-test',
        label: 'Random Key Generation (16 bytes)',
        fn: async () => {
          const key = await randomKey(16);
          // Should be 32 hex characters for 16 bytes
          const hexRegex = /^[0-9a-f]{32}$/i;
          return hexRegex.test(key)
            ? `VALID KEY (${key.length} chars)`
            : `INVALID: ${key}`;
        },
        expected: 'VALID KEY (32 chars)',
      },
      {
        key: 'random-bytes-test',
        label: 'Random Bytes Generation (32 bytes)',
        fn: async () => {
          const bytes = await randomBytes(32);
          // Should be base64 encoded - roughly 4/3 the size, so ~43 chars for 32 bytes
          const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
          const expectedLength = Math.ceil((32 * 4) / 3);
          const isValidBase64 = base64Regex.test(bytes);
          const isCorrectLength =
            bytes.length >= expectedLength - 2 &&
            bytes.length <= expectedLength + 2;

          if (isValidBase64 && isCorrectLength) {
            return `VALID BYTES (${bytes.length} chars)`;
          } else {
            return `INVALID: ${bytes} (length: ${bytes.length}, expected: ~${expectedLength})`;
          }
        },
        expected: 'VALID BYTES',
      },
      {
        key: 'random-bytes-small-test',
        label: 'Random Bytes Generation (8 bytes)',
        fn: async () => {
          const bytes = await randomBytes(8);
          // 8 bytes -> 12 base64 chars (with padding)
          const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
          return base64Regex.test(bytes) &&
            bytes.length >= 10 &&
            bytes.length <= 12
            ? `VALID (${bytes.length} chars)`
            : `INVALID: ${bytes}`;
        },
        expected: 'VALID',
      },
      {
        key: 'rsa-keygen-test',
        label: 'RSA Key Generation (2048-bit)',
        fn: async () => {
          const keyPair = await rsaGenerateKeys(2048);
          const hasPublic = keyPair.public.includes('BEGIN PUBLIC KEY');
          const hasPrivate = keyPair.private.includes('BEGIN PRIVATE KEY');
          return hasPublic && hasPrivate ? 'VALID KEYPAIR' : 'INVALID';
        },
        expected: 'VALID KEYPAIR',
      },
      {
        key: 'rsa-roundtrip-test',
        label: 'RSA Encrypt to Decrypt Roundtrip',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);
            const message = 'Hello RSA World!';

            const encrypted = await rsaEncrypt(message, keyPair.public);
            const decrypted = await rsaDecrypt(encrypted, keyPair.private);

            return decrypted === message ? 'PASS' : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'PASS',
      },
      {
        key: 'rsa-sign-verify-test',
        label: 'RSA Sign to Verify Roundtrip',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);
            const message = 'Hello RSA Signature!';

            const signature = await rsaSign(message, keyPair.private, 'SHA256');
            const verified = await rsaVerify(
              signature,
              message,
              keyPair.public,
              'SHA256'
            );

            return verified ? 'PASS' : 'FAIL: signature not verified';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'PASS',
      },
      {
        key: 'random-values-test',
        label: 'Random Alphanumeric Values (10 chars)',
        fn: async () => {
          const values = await getRandomValues(10);
          const alphanumericRegex = /^[A-Za-z0-9]{10}$/;
          return alphanumericRegex.test(values)
            ? `VALID: ${values}`
            : `INVALID: ${values}`;
        },
        expected: 'VALID:',
      },
      {
        key: 'rsa-jwk-export-test',
        label: 'RSA Export Key to JWK Format',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);
            const jwk = await rsaExportKey(keyPair.private);

            const hasRequiredProps =
              jwk.kty === 'RSA' &&
              jwk.n &&
              jwk.e &&
              jwk.d &&
              jwk.p &&
              jwk.q &&
              jwk.dp &&
              jwk.dq &&
              jwk.qi;

            return hasRequiredProps ? 'VALID JWK' : 'INVALID JWK';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'VALID JWK',
      },
      {
        key: 'rsa-jwk-import-test',
        label: 'RSA Import JWK to PEM Format',
        fn: async () => {
          try {
            // Generate a real RSA key pair first
            const keyPair = await rsaGenerateKeys(2048);

            // Export the public key to JWK format
            const publicJwk = await rsaExportKey(keyPair.public);

            // Remove private key components to make it a public-only JWK
            const publicOnlyJwk: JWK = {
              kty: publicJwk.kty,
              n: publicJwk.n,
              e: publicJwk.e,
            };

            // Now try to import the JWK back to PEM
            const pem = await rsaImportKey(publicOnlyJwk);
            const isValidPem =
              pem.includes('-----BEGIN RSA PUBLIC KEY-----') &&
              pem.includes('-----END RSA PUBLIC KEY-----');

            return isValidPem ? 'VALID PEM' : 'INVALID PEM';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'VALID PEM',
      },
      {
        key: 'rsa-jwk-roundtrip-test',
        label: 'RSA JWK to PEM to JWK Roundtrip',
        fn: async () => {
          try {
            const keyPair = await rsaGenerateKeys(2048);

            // Export PEM to JWK
            const originalJwk = await rsaExportKey(keyPair.private);

            // Import JWK to PEM
            const pemFromJwk = await rsaImportKey(originalJwk);

            // Export PEM back to JWK
            const roundtripJwk = await rsaExportKey(pemFromJwk);

            // Compare key properties (n should be the same)
            const isEqual =
              originalJwk.n === roundtripJwk.n &&
              originalJwk.e === roundtripJwk.e &&
              originalJwk.d === roundtripJwk.d;

            return isEqual ? 'ROUNDTRIP PASS' : 'ROUNDTRIP FAIL';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'ROUNDTRIP PASS',
      },
      {
        key: 'rsa-encrypt-pkcs1-test',
        label: 'RSA Encrypt with PKCS#1 Key (from JWK)',
        fn: async () => {
          try {
            // Generate a key pair and export to JWK
            const keyPair = await rsaGenerateKeys(2048);
            const publicJwk = await rsaExportKey(keyPair.public);

            // Import JWK to get PKCS#1 format key
            const pkcs1PublicKey = await rsaImportKey(publicJwk);

            // Verify it's PKCS#1 format (contains "RSA PUBLIC KEY")
            if (!pkcs1PublicKey.includes('RSA PUBLIC KEY')) {
              return 'ERROR: Expected PKCS#1 format key';
            }

            const message = 'Test PKCS#1 encryption!';

            // Test encryption with PKCS#1 key
            const encrypted = await rsaEncrypt(message, pkcs1PublicKey);

            // Decrypt with original private key to verify
            const decrypted = await rsaDecrypt(encrypted, keyPair.private);

            return decrypted === message
              ? 'PKCS#1 ENCRYPT OK'
              : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'PKCS#1 ENCRYPT OK',
      },
      {
        key: 'rsa-encrypt-x509-test',
        label: 'RSA Encrypt with X.509 Key (standard)',
        fn: async () => {
          try {
            // Generate standard X.509 key pair
            const keyPair = await rsaGenerateKeys(2048);

            // Verify it's X.509 format (contains "PUBLIC KEY")
            if (
              !keyPair.public.includes('PUBLIC KEY') ||
              keyPair.public.includes('RSA PUBLIC KEY')
            ) {
              return 'ERROR: Expected X.509 format key';
            }

            const message = 'Test X.509 encryption!';

            // Test encryption with X.509 key
            const encrypted = await rsaEncrypt(message, keyPair.public);
            const decrypted = await rsaDecrypt(encrypted, keyPair.private);

            return decrypted === message
              ? 'X.509 ENCRYPT OK'
              : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'X.509 ENCRYPT OK',
      },
      {
        key: 'rsa-kat-decrypt-test',
        label: 'RSA OAEP-SHA256 Decrypt (fixed vector)',
        fn: async () => {
          try {
            const decrypted = await rsaDecrypt(
              RSA_FIXED_OAEP_CIPHERTEXT_B64,
              RSA_FIXED_PRIVATE_KEY!
            );
            return decrypted === RSA_FIXED_PLAINTEXT
              ? 'KAT DECRYPT OK'
              : `FAIL: got "${decrypted}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'KAT DECRYPT OK',
      },
      {
        key: 'rsa-kat-verify-test',
        label: 'RSA PKCS#1 v1.5 SHA-256 Verify (fixed vector)',
        fn: async () => {
          try {
            const verified = await rsaVerify(
              RSA_FIXED_SIGNATURE_B64,
              RSA_FIXED_SIGN_MESSAGE,
              RSA_FIXED_PUBLIC_KEY!,
              'SHA256'
            );
            return verified ? 'KAT VERIFY OK' : 'FAIL: signature rejected';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'KAT VERIFY OK',
      },
      {
        key: 'rsa-kat-sign-test',
        label: 'RSA PKCS#1 v1.5 SHA-256 Sign (deterministic, exact)',
        fn: async () => {
          try {
            const signature = await rsaSign(
              RSA_FIXED_SIGN_MESSAGE,
              RSA_FIXED_PRIVATE_KEY!,
              'SHA256'
            );
            return signature === RSA_FIXED_SIGNATURE_B64
              ? 'KAT SIGN OK'
              : `FAIL: got "${signature}"`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'KAT SIGN OK',
      },
      {
        key: 'rsa-kat-jwk-export-test',
        label: 'RSA Export Key to JWK (fixed n/e)',
        fn: async () => {
          try {
            const jwk = await rsaExportKey(RSA_FIXED_PUBLIC_KEY!);
            return jwk.kty === 'RSA' &&
              jwk.n === RSA_FIXED_JWK.n &&
              jwk.e === RSA_FIXED_JWK.e
              ? 'KAT JWK EXPORT OK'
              : `FAIL: n=${jwk.n} e=${jwk.e}`;
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'KAT JWK EXPORT OK',
      },
      {
        key: 'rsa-kat-jwk-import-test',
        label: 'RSA Import JWK then Verify (fixed vector)',
        fn: async () => {
          try {
            const importedPem = await rsaImportKey(RSA_FIXED_JWK);
            const verified = await rsaVerify(
              RSA_FIXED_SIGNATURE_B64,
              RSA_FIXED_SIGN_MESSAGE,
              importedPem,
              'SHA256'
            );
            return verified
              ? 'KAT JWK IMPORT OK'
              : 'FAIL: imported key rejected signature';
          } catch (error) {
            return `ERROR: ${error}`;
          }
        },
        expected: 'KAT JWK IMPORT OK',
      },
    ];

    for (const test of tests) {
      try {
        setLoading((prev) => ({ ...prev, [test.key]: true }));
        const result = await test.fn();
        let isCorrect = false;

        if (test.key === 'aes-encrypt-test') {
          // For AES encrypt, just verify it's not null and not the original base64
          isCorrect =
            result !== 'null' &&
            result !== 'SGVsbG8gV29ybGQ=' &&
            result.length > 0;
        } else if (test.key === 'aes-gcm-encrypt-test') {
          // For AES-GCM encrypt, just verify it's not null and not the original base64
          isCorrect =
            result !== 'null' &&
            result !== 'SGVsbG8gV29ybGQ=' &&
            result.length > 0;
        } else if (test.key === 'random-bytes-test') {
          // For random bytes, check if result starts with "VALID BYTES"
          isCorrect = result.startsWith('VALID BYTES');
        } else if (test.key === 'random-bytes-small-test') {
          // For small random bytes, check if result starts with "VALID"
          isCorrect = result.startsWith('VALID');
        } else if (test.key === 'random-values-test') {
          // For random values, check if result starts with "VALID:"
          isCorrect = result.startsWith('VALID:');
        } else {
          isCorrect = result.toLowerCase() === test.expected.toLowerCase();
        }

        setResults((prev) => ({
          ...prev,
          [test.key]: `${result} ${isCorrect ? '✓' : '✗'}`,
        }));
      } catch (error) {
        setResults((prev) => ({
          ...prev,
          [test.key]: `Error: ${error}`,
        }));
      } finally {
        setLoading((prev) => ({ ...prev, [test.key]: false }));
      }
    }
  };

  useEffect(() => {
    runCryptoTests();
  }, []);

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container}>
        <ScrollView
          style={styles.container}
          contentContainerStyle={styles.content}
        >
          <Text style={styles.title}>Mobile Crypto Test</Text>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>SHA Tests:</Text>

            <Text style={styles.testLabel}>SHA-256 UTF-8 ("hello"):</Text>
            <Text style={styles.result}>
              {loading['utf8-sha256']
                ? 'Loading...'
                : results['utf8-sha256'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>SHA-1 UTF-8 ("hello"):</Text>
            <Text style={styles.result}>
              {loading['utf8-sha1']
                ? 'Loading...'
                : results['utf8-sha1'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>SHA-256 Base64 ("aGVsbG8="):</Text>
            <Text style={styles.result}>
              {loading['base64-sha256']
                ? 'Loading...'
                : results['base64-sha256'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>SHA-512 UTF-8 ("test"):</Text>
            <Text style={styles.result}>
              {loading['utf8-sha512']
                ? 'Loading...'
                : results['utf8-sha512'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>PBKDF2 Tests:</Text>

            <Text style={styles.testLabel}>
              PBKDF2-SHA256 (pwd="password", salt="salt", iter=1000, len=32):
            </Text>
            <Text style={styles.result}>
              {loading['pbkdf2-sha256']
                ? 'Loading...'
                : results['pbkdf2-sha256'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              PBKDF2-SHA1 (pwd="password", salt="salt", iter=1000, len=20):
            </Text>
            <Text style={styles.result}>
              {loading['pbkdf2-sha1']
                ? 'Loading...'
                : results['pbkdf2-sha1'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>HMAC Tests:</Text>

            <Text style={styles.testLabel}>
              HMAC-SHA256 (data="Hello", key="key"):
            </Text>
            <Text style={styles.result}>
              {loading['hmac256-test1']
                ? 'Loading...'
                : results['hmac256-test1'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              HMAC-SHA256 (data="test", key="key"):
            </Text>
            <Text style={styles.result}>
              {loading['hmac256-test2']
                ? 'Loading...'
                : results['hmac256-test2'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>AES & Crypto Utils Tests:</Text>

            <Text style={styles.testLabel}>AES Encrypt (Hello World):</Text>
            <Text style={styles.result}>
              {loading['aes-encrypt-test']
                ? 'Loading...'
                : results['aes-encrypt-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              AES Encrypt to Decrypt Roundtrip:
            </Text>
            <Text style={styles.result}>
              {loading['aes-roundtrip-test']
                ? 'Loading...'
                : results['aes-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              AES-256-GCM Encrypt (Hello World):
            </Text>
            <Text style={styles.result}>
              {loading['aes-gcm-encrypt-test']
                ? 'Loading...'
                : results['aes-gcm-encrypt-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              AES-256-GCM Encrypt to Decrypt Roundtrip:
            </Text>
            <Text style={styles.result}>
              {loading['aes-gcm-roundtrip-test']
                ? 'Loading...'
                : results['aes-gcm-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              AES-256-GCM Authentication Test (wrong key):
            </Text>
            <Text style={styles.result}>
              {loading['aes-gcm-auth-test']
                ? 'Loading...'
                : results['aes-gcm-auth-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>Random UUID Generation:</Text>
            <Text style={styles.result}>
              {loading['random-uuid-test']
                ? 'Loading...'
                : results['random-uuid-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Key Generation (16 bytes):
            </Text>
            <Text style={styles.result}>
              {loading['random-key-test']
                ? 'Loading...'
                : results['random-key-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Bytes Generation (32 bytes):
            </Text>
            <Text style={styles.result}>
              {loading['random-bytes-test']
                ? 'Loading...'
                : results['random-bytes-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Bytes Generation (8 bytes):
            </Text>
            <Text style={styles.result}>
              {loading['random-bytes-small-test']
                ? 'Loading...'
                : results['random-bytes-small-test'] || 'Not run'}
            </Text>
          </View>

          <View style={styles.section}>
            <Text style={styles.sectionTitle}>
              RSA & Advanced Crypto Tests:
            </Text>

            <Text style={styles.testLabel}>RSA Key Generation (2048-bit):</Text>
            <Text style={styles.result}>
              {loading['rsa-keygen-test']
                ? 'Loading...'
                : results['rsa-keygen-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Encrypt to Decrypt Roundtrip:
            </Text>
            <Text style={styles.result}>
              {loading['rsa-roundtrip-test']
                ? 'Loading...'
                : results['rsa-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA Sign to Verify Roundtrip:</Text>
            <Text style={styles.result}>
              {loading['rsa-sign-verify-test']
                ? 'Loading...'
                : results['rsa-sign-verify-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              Random Alphanumeric Values (10 chars):
            </Text>
            <Text style={styles.result}>
              {loading['random-values-test']
                ? 'Loading...'
                : results['random-values-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA Export Key to JWK Format:</Text>
            <Text style={styles.result}>
              {loading['rsa-jwk-export-test']
                ? 'Loading...'
                : results['rsa-jwk-export-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA Import JWK to PEM Format:</Text>
            <Text style={styles.result}>
              {loading['rsa-jwk-import-test']
                ? 'Loading...'
                : results['rsa-jwk-import-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>RSA JWK ↔ PEM Roundtrip Test:</Text>
            <Text style={styles.result}>
              {loading['rsa-jwk-roundtrip-test']
                ? 'Loading...'
                : results['rsa-jwk-roundtrip-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Encrypt with PKCS#1 Key (from JWK):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-encrypt-pkcs1-test']
                ? 'Loading...'
                : results['rsa-encrypt-pkcs1-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Encrypt with X.509 Key (standard):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-encrypt-x509-test']
                ? 'Loading...'
                : results['rsa-encrypt-x509-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA OAEP-SHA256 Decrypt (fixed vector):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-kat-decrypt-test']
                ? 'Loading...'
                : results['rsa-kat-decrypt-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA PKCS#1 v1.5 SHA-256 Verify (fixed vector):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-kat-verify-test']
                ? 'Loading...'
                : results['rsa-kat-verify-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA PKCS#1 v1.5 SHA-256 Sign (deterministic, exact):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-kat-sign-test']
                ? 'Loading...'
                : results['rsa-kat-sign-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Export Key to JWK (fixed n/e):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-kat-jwk-export-test']
                ? 'Loading...'
                : results['rsa-kat-jwk-export-test'] || 'Not run'}
            </Text>

            <Text style={styles.testLabel}>
              RSA Import JWK then Verify (fixed vector):
            </Text>
            <Text style={styles.result}>
              {loading['rsa-kat-jwk-import-test']
                ? 'Loading...'
                : results['rsa-kat-jwk-import-test'] || 'Not run'}
            </Text>
          </View>

          <Button title="Run Tests Again" onPress={runCryptoTests} />
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  content: {
    padding: 20,
  },
  title: {
    fontSize: 24,
    fontWeight: 'bold',
    textAlign: 'center',
    marginBottom: 20,
  },
  section: {
    backgroundColor: 'white',
    padding: 15,
    marginBottom: 15,
    borderRadius: 8,
  },
  sectionTitle: {
    fontSize: 18,
    fontWeight: 'bold',
    marginBottom: 10,
  },
  testLabel: {
    fontSize: 14,
    fontWeight: 'bold',
    marginTop: 10,
    marginBottom: 5,
  },
  result: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#333',
    backgroundColor: '#f8f8f8',
    padding: 8,
    borderRadius: 4,
  },
});
