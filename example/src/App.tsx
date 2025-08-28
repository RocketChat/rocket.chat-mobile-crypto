import { useState, useEffect } from 'react';
import { Text, View, StyleSheet, ScrollView, Button } from 'react-native';
import {
  multiply,
  shaBase64,
  shaUtf8,
  pbkdf2Hash,
  hmac256,
} from '@rocket.chat/mobile-crypto';

export default function App() {
  const [results, setResults] = useState<{ [key: string]: string }>({});
  const [loading, setLoading] = useState<{ [key: string]: boolean }>({});

  const multiplyResult = multiply(3, 7);

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
    ];

    for (const test of tests) {
      try {
        setLoading((prev) => ({ ...prev, [test.key]: true }));
        const result = await test.fn();
        const isCorrect = result.toLowerCase() === test.expected.toLowerCase();
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
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.title}>Mobile Crypto Test</Text>

      <View style={styles.section}>
        <Text style={styles.sectionTitle}>Multiply Test:</Text>
        <Text>3 × 7 = {multiplyResult}</Text>
      </View>

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

      <Button title="Run Tests Again" onPress={runCryptoTests} />
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f5f5f5',
  },
  content: {
    padding: 20,
    paddingBottom: 80,
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
