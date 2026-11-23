import { useCallback, useEffect, useState } from 'react';
import { Button, ScrollView, StyleSheet, Text, View } from 'react-native';
import {
  aesCbcDecrypt,
  aesCbcEncrypt,
  aesDeriveKey,
  aesGcmDecrypt,
  aesGcmEncrypt,
  aesGenerateKey,
  hmac256,
  randomBytes,
  randomKey,
  randomUuid,
  rsaDecrypt,
  rsaEncrypt,
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaSign,
  rsaVerify,
  sha,
} from '@rocket.chat/mobile-crypto';
import { SafeAreaProvider, SafeAreaView } from 'react-native-safe-area-context';

type Check = {
  label: string;
  expected: string;
  run: () => Promise<string>;
};

const message = 'Rocket.Chat 🔐';

const bufferFromText = (text: string): ArrayBuffer =>
  new TextEncoder().encode(text).buffer as ArrayBuffer;

const base64FromBuffer = (buffer: ArrayBuffer): string =>
  btoa(String.fromCharCode(...new Uint8Array(buffer)));

const checks: Check[] = [
  {
    label: 'SHA-256 ("hello")',
    expected: 'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=',
    run: async () =>
      base64FromBuffer(await sha(bufferFromText('hello'), 'SHA-256')),
  },
  {
    label: 'HMAC-SHA256 (data "Hello", key "key")',
    expected: 'xwufTWZb1il0r8g1gt6BDnKkGljbgsU4qdc0ySZtMh4=',
    run: async () =>
      base64FromBuffer(
        await hmac256(bufferFromText('Hello'), bufferFromText('key'))
      ),
  },
  {
    label: 'PBKDF2-SHA256 ("password", "salt", 1000, 32 bytes)',
    expected: 'YywoEuRtRgQQK6dhjp1tfS-BKPYma0oDJk0qBGC33LM',
    run: async () =>
      (
        await aesDeriveKey(btoa('password'), btoa('salt'), 1000, 32, 'SHA256')
      ).exportBase64Url(),
  },
  {
    label: 'AES-256-GCM encrypt then decrypt',
    expected: message,
    run: async () => {
      const key = aesGenerateKey(32);
      return aesGcmDecrypt(key, await aesGcmEncrypt(key, message));
    },
  },
  {
    label: 'AES-256-CBC encrypt then decrypt',
    expected: message,
    run: async () => {
      const key = aesGenerateKey(32);
      return aesCbcDecrypt(key, await aesCbcEncrypt(key, message));
    },
  },
  {
    label: 'RSA-OAEP encrypt then decrypt',
    expected: message,
    run: async () => {
      const { publicKey, privateKey } = await rsaGenerateKeys(2048);
      return rsaDecrypt(privateKey, await rsaEncrypt(publicKey, message));
    },
  },
  {
    label: 'RSA PKCS#1 v1.5 sign then verify',
    expected: 'true',
    run: async () => {
      const { publicKey, privateKey } = await rsaGenerateKeys(2048);
      const bytes = bufferFromText(message);
      const signature = await rsaSign(privateKey, bytes, 'SHA256');
      return String(await rsaVerify(publicKey, signature, bytes, 'SHA256'));
    },
  },
  {
    label: 'RSA private key JWK export then import',
    expected: 'true',
    run: async () => {
      const { privateKey } = await rsaGenerateKeys(2048);
      const jwk = privateKey.exportJwk();
      return String((await rsaImportPrivateKey(jwk)).exportJwk() === jwk);
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
    label: 'Random key (16 bytes) as lowercase hex',
    expected: 'true',
    run: async () => String(/^[0-9a-f]{32}$/.test(randomKey(16))),
  },
  {
    label: 'Random bytes (32)',
    expected: '32',
    run: async () => String(randomBytes(32).byteLength),
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
          <Text style={styles.title}>Mobile Crypto</Text>
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
