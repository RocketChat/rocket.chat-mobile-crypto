import { useCallback, useEffect, useState } from 'react';
import { Button, ScrollView, StyleSheet, Text, View } from 'react-native';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  aesDeriveKey,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesGenerateKey,
  aesImportKey,
  hmac256,
  randomBytes,
  randomKey,
  randomUuid,
  rsaDecrypt,
  rsaEncrypt,
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  rsaSign,
  rsaVerify,
  sha,
} from '@rocket.chat/mobile-crypto';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';
import {
  RSA_FIXED_OAEP_CIPHERTEXT,
  RSA_FIXED_PLAINTEXT,
  RSA_FIXED_PRIVATE_JWK,
  RSA_FIXED_PUBLIC_JWK,
  RSA_FIXED_SIGNATURE,
  RSA_FIXED_SIGN_MESSAGE,
} from '../fixtures/rsa';
import {
  base64FromBuffer,
  bufferFromAscii,
  bufferFromBase64,
} from '../fixtures/bytes';
import {
  cbcVectors,
  gcmVectors,
  hashVectors,
  passwordBase64,
  pbkdf2Vectors,
  saltBase64,
  unicodeVector,
} from '../fixtures/crypto';

type Check = {
  label: string;
  expected: string;
  run: () => Promise<string>;
};

const gcmVector = gcmVectors[1]!;
const cbcVector = cbcVectors[1]!;
const pbkdf2Vector = pbkdf2Vectors[2];

const checks: Check[] = [
  ...hashVectors.map(
    (vector): Check => ({
      label: `${vector.algorithm} ("hello")`,
      expected: vector.base64,
      run: async () =>
        base64FromBuffer(await sha(bufferFromAscii('hello'), vector.algorithm)),
    })
  ),
  {
    label: 'HMAC-SHA256 (data "Hello", key "key")',
    expected: 'xwufTWZb1il0r8g1gt6BDnKkGljbgsU4qdc0ySZtMh4=',
    run: async () =>
      base64FromBuffer(
        await hmac256(bufferFromAscii('Hello'), bufferFromAscii('key'))
      ),
  },
  {
    label: `PBKDF2-${pbkdf2Vector.algorithm} ("password", "salt", 1000, ${pbkdf2Vector.byteLength})`,
    expected: pbkdf2Vector.expected,
    run: async () =>
      (
        await aesDeriveKey(
          passwordBase64,
          saltBase64,
          1000,
          pbkdf2Vector.byteLength,
          pbkdf2Vector.algorithm
        )
      ).exportBase64Url(),
  },
  {
    label: 'AES-256-GCM decrypt (fixed vector)',
    expected: gcmVector.plaintext,
    run: () =>
      aesGcmDecrypt(aesImportKey(gcmVector.key), {
        ciphertext: gcmVector.ciphertext,
        iv: gcmVector.iv,
      }),
  },
  {
    label: 'AES-256-GCM encrypt then decrypt',
    expected: 'Hello World',
    run: async () => {
      const key = aesGenerateKey(32);
      return aesGcmDecrypt(key, await aesGcmEncrypt(key, 'Hello World'));
    },
  },
  {
    label: 'AES-256-GCM decrypt with the wrong key',
    expected: 'rejected',
    run: async () => {
      const encrypted = await aesGcmEncrypt(aesGenerateKey(32), 'Hello World');
      return aesGcmDecrypt(aesGenerateKey(32), encrypted).then(
        () => 'accepted',
        () => 'rejected'
      );
    },
  },
  {
    label: 'AES-256-CBC decrypt (fixed vector)',
    expected: cbcVector.plaintext,
    run: () =>
      aesCbcDecrypt(aesImportKey(cbcVector.key), cbcVector.ivAndCiphertext),
  },
  {
    label: 'AES-256-CBC encrypt then decrypt',
    expected: 'Hello World',
    run: async () => {
      const key = aesGenerateKey(32);
      return aesCbcDecrypt(key, await aesCbcEncrypt(key, 'Hello World'));
    },
  },
  {
    label: 'Random UUID is version 4',
    expected: 'true',
    run: async () =>
      String(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
          randomUuid()
        )
      ),
  },
  {
    label: 'Random key (16 bytes) as hexadecimal',
    expected: 'true',
    run: async () => String(/^[0-9a-f]{32}$/i.test(randomKey(16))),
  },
  {
    label: 'Random bytes (32)',
    expected: '32',
    run: async () => String(randomBytes(32).byteLength),
  },
  {
    label: 'RSA OAEP-SHA256 decrypt (fixed vector)',
    expected: RSA_FIXED_PLAINTEXT,
    run: async () =>
      rsaDecrypt(
        await rsaImportPrivateKey(RSA_FIXED_PRIVATE_JWK),
        RSA_FIXED_OAEP_CIPHERTEXT
      ),
  },
  {
    label: 'RSA PKCS#1 v1.5 SHA-256 sign (fixed vector)',
    expected: RSA_FIXED_SIGNATURE,
    run: async () =>
      base64FromBuffer(
        await rsaSign(
          await rsaImportPrivateKey(RSA_FIXED_PRIVATE_JWK),
          bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
          'SHA256'
        )
      ),
  },
  {
    label: 'RSA PKCS#1 v1.5 SHA-256 verify (fixed vector)',
    expected: 'true',
    run: async () =>
      String(
        await rsaVerify(
          await rsaImportPublicKey(RSA_FIXED_PUBLIC_JWK),
          bufferFromBase64(RSA_FIXED_SIGNATURE),
          bufferFromAscii(RSA_FIXED_SIGN_MESSAGE),
          'SHA256'
        )
      ),
  },
  {
    label: 'RSA private key JWK export (fixed key)',
    expected: RSA_FIXED_PRIVATE_JWK,
    run: async () =>
      (await rsaImportPrivateKey(RSA_FIXED_PRIVATE_JWK)).exportJwk(),
  },
  {
    label: 'RSA generated keys encrypt then decrypt',
    expected: unicodeVector.text,
    run: async () => {
      const { publicKey, privateKey } = await rsaGenerateKeys(2048);
      return rsaDecrypt(
        privateKey,
        await rsaEncrypt(publicKey, unicodeVector.text)
      );
    },
  },
  {
    label: 'RSA generated key JWK export then import',
    expected: 'true',
    run: async () => {
      const { privateKey } = await rsaGenerateKeys(2048);
      const jwk = privateKey.exportJwk();
      return String((await rsaImportPrivateKey(jwk)).exportJwk() === jwk);
    },
  },
];

const runCheck = (check: Check) =>
  Promise.resolve()
    .then(check.run)
    .catch((error: unknown) => `Error: ${String(error)}`);

function useCheckResults() {
  const [results, setResults] = useState<Record<string, string>>({});

  const runChecks = useCallback(async () => {
    setResults({});
    for (const check of checks) {
      const result = await runCheck(check);
      setResults((previous) => ({ ...previous, [check.label]: result }));
    }
  }, []);

  useEffect(() => {
    runChecks();
  }, [runChecks]);

  return { results, runChecks };
}

export default function App() {
  const { results, runChecks } = useCheckResults();

  return (
    <SafeAreaProvider>
      <SafeAreaView style={styles.container}>
        <ScrollView
          style={styles.container}
          contentContainerStyle={styles.content}
        >
          <Text style={styles.title}>Mobile Crypto Known Answers</Text>
          {checks.map((check) => (
            <CheckRow
              key={check.label}
              check={check}
              result={results[check.label]}
            />
          ))}
          <Button title="Run Checks Again" onPress={runChecks} />
        </ScrollView>
      </SafeAreaView>
    </SafeAreaProvider>
  );
}

function CheckRow({ check, result }: { check: Check; result?: string }) {
  const status =
    result === undefined ? '…' : result === check.expected ? '✓' : '✗';

  return (
    <View style={styles.check}>
      <Text style={styles.label}>
        {status} {check.label}
      </Text>
      <Text style={styles.result}>{result ?? 'Running'}</Text>
    </View>
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
  check: {
    backgroundColor: 'white',
    padding: 12,
    marginBottom: 10,
    borderRadius: 8,
  },
  label: {
    fontSize: 14,
    fontWeight: 'bold',
    marginBottom: 5,
  },
  result: {
    fontSize: 12,
    fontFamily: 'monospace',
    color: '#333',
  },
});
