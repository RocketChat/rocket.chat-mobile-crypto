import { useState, useEffect } from 'react';
import { Text, View, StyleSheet, ScrollView, Button } from 'react-native';
import { multiply, shaBase64, shaUtf8 } from '@rocket.chat/mobile-crypto';

export default function App() {
  const [results, setResults] = useState<{ [key: string]: string }>({});
  const [loading, setLoading] = useState<{ [key: string]: boolean }>({});

  const multiplyResult = multiply(3, 7);

  const runShaTests = async () => {
    const tests = [
      {
        key: 'utf8-sha256',
        label: 'SHA-256 UTF-8 ("hello")',
        fn: () => shaUtf8('hello', 'SHA-256'),
        expected:
          '2cf24dba4f21d4288094c973db33b0b3d0b2f44dacd3b11b894c62b7e57b33d2',
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
        expected: 'LPJNuk8h1CiAlMlz2zOwvdCy9E2s07EbiUxityXls9I=',
      },
      {
        key: 'utf8-sha512',
        label: 'SHA-512 UTF-8 ("test")',
        fn: () => shaUtf8('test', 'SHA-512'),
        expected:
          '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
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
    runShaTests();
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

      <Button title="Run Tests Again" onPress={runShaTests} />
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
