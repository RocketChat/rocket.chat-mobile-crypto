# @rocket.chat/mobile-crypto

Rocket.Chat Mobile Crypto - A comprehensive cryptographic library for React Native applications.

## Installation

```sh
npm install @rocket.chat/mobile-crypto
```

## Usage

### SHA Functions

Generate SHA hashes from UTF-8 strings or Base64 data:

```js
import { shaBase64, shaUtf8 } from '@rocket.chat/mobile-crypto';

// SHA from UTF-8 string
const sha256Hash = await shaUtf8('hello', 'SHA-256');
const sha1Hash = await shaUtf8('hello', 'SHA-1');
const sha512Hash = await shaUtf8('test', 'SHA-512');

// SHA from Base64 data
const sha256FromBase64 = await shaBase64('aGVsbG8=', 'SHA-256'); // "hello" in base64
```

### PBKDF2 Key Derivation

Generate cryptographic keys from passwords using PBKDF2:

```js
import { pbkdf2Hash } from '@rocket.chat/mobile-crypto';

const derivedKey = await pbkdf2Hash(
  'cGFzc3dvcmQ=', // password in base64
  'c2FsdA==', // salt in base64
  1000, // iterations
  32, // key length
  'SHA256' // hash algorithm
);
```

### HMAC Authentication

Generate HMAC-SHA256 for message authentication:

```js
import { hmac256 } from '@rocket.chat/mobile-crypto';

const hmac = await hmac256(
  '48656c6c6f', // data in hex ("Hello")
  '6b6579' // key in hex ("key")
);
```

### AES Encryption/Decryption

Encrypt and decrypt data using AES:

```js
import {
  aesEncrypt,
  aesDecrypt,
  aesEncryptFile,
  aesDecryptFile,
} from '@rocket.chat/mobile-crypto';

// String encryption/decryption
const encrypted = await aesEncrypt(
  'SGVsbG8gV29ybGQ=', // data in base64
  '0123456789abcdef0123456789abcdef', // key in hex
  'fedcba9876543210fedcba9876543210' // IV in hex
);

const decrypted = await aesDecrypt(encrypted, key, iv);

// File encryption/decryption
const encryptedFilePath = await aesEncryptFile(
  '/path/to/file',
  'base64UrlKey',
  'base64Iv'
);

const decryptedFilePath = await aesDecryptFile(
  '/path/to/encrypted/file',
  'base64UrlKey',
  'base64Iv'
);
```

### Random Generation

Generate cryptographically secure random values:

```js
import {
  randomUuid,
  randomKey,
  randomBytes,
  getRandomValues,
} from '@rocket.chat/mobile-crypto';

// Generate UUID
const uuid = await randomUuid(); // e.g., "123e4567-e89b-12d3-a456-426614174000"

// Generate random key (returns hex string)
const key = await randomKey(16); // 16 bytes = 32 hex characters

// Generate random bytes (returns base64 string)
const bytes = await randomBytes(32); // 32 random bytes in base64

// Generate random alphanumeric string
const randomString = await getRandomValues(10); // 10 character alphanumeric string
```

### RSA Encryption/Decryption and Digital Signatures

Full RSA support for encryption, decryption, signing, and verification:

```js
import {
  rsaGenerateKeys,
  rsaEncrypt,
  rsaEncrypt64,
  rsaDecrypt,
  rsaDecrypt64,
  rsaSign,
  rsaSign64,
  rsaVerify,
  rsaVerify64,
} from '@rocket.chat/mobile-crypto';

// Generate RSA key pair
const keyPair = await rsaGenerateKeys(2048); // 2048-bit keys
// Returns: { public: string, private: string }

// Encryption/Decryption
const encrypted = await rsaEncrypt('Hello RSA!', keyPair.public);
const decrypted = await rsaDecrypt(encrypted, keyPair.private);

// Base64 variants
const encrypted64 = await rsaEncrypt64('Hello RSA!', keyPair.public);
const decrypted64 = await rsaDecrypt64(encrypted64, keyPair.private);

// Digital signatures
const signature = await rsaSign('Message to sign', keyPair.private, 'SHA256');
const isValid = await rsaVerify(
  signature,
  'Message to sign',
  keyPair.public,
  'SHA256'
);

// Base64 signature variants
const signature64 = await rsaSign64(
  'Message to sign',
  keyPair.private,
  'SHA256'
);
const isValid64 = await rsaVerify64(
  signature64,
  'Message to sign',
  keyPair.public,
  'SHA256'
);
```

### Utility Functions

Additional utility functions for file operations:

```js
import { calculateFileChecksum } from '@rocket.chat/mobile-crypto';

// Calculate file checksum
const checksum = await calculateFileChecksum('/path/to/file');
```

## API Reference

### Hash Functions

- `shaBase64(data: string, algorithm: string): Promise<string>` - SHA hash from base64 data
- `shaUtf8(data: string, algorithm: string): Promise<string>` - SHA hash from UTF-8 string

### Key Derivation

- `pbkdf2Hash(pwdBase64: string, saltBase64: string, iterations: number, keyLen: number, hash: string): Promise<string>` - PBKDF2 key derivation

### Message Authentication

- `hmac256(data: string, key: string): Promise<string>` - HMAC-SHA256

### Symmetric Encryption

- `aesEncrypt(dataBase64: string, keyHex: string, ivHex: string): Promise<string>` - AES encryption
- `aesDecrypt(dataBase64: string, keyHex: string, ivHex: string): Promise<string>` - AES decryption
- `aesEncryptFile(filePath: string, base64UrlKey: string, base64Iv: string): Promise<string>` - AES file encryption
- `aesDecryptFile(filePath: string, base64UrlKey: string, base64Iv: string): Promise<string>` - AES file decryption

### Random Generation

- `randomUuid(): Promise<string>` - Generate random UUID
- `randomKey(length: number): Promise<string>` - Generate random key (hex)
- `randomBytes(size: number): Promise<string>` - Generate random bytes (base64)
- `getRandomValues(length: number): Promise<string>` - Generate random alphanumeric string

### Asymmetric Encryption (RSA)

- `rsaGenerateKeys(keySize?: number): Promise<{ public: string; private: string }>` - Generate RSA key pair
- `rsaEncrypt(message: string, publicKey: string): Promise<string>` - RSA encryption
- `rsaEncrypt64(message: string, publicKey: string): Promise<string>` - RSA encryption (base64)
- `rsaDecrypt(encodedMessage: string, privateKey: string): Promise<string>` - RSA decryption
- `rsaDecrypt64(encodedMessage: string, privateKey: string): Promise<string>` - RSA decryption (base64)

### Digital Signatures (RSA)

- `rsaSign(message: string, privateKey: string, hash?: string): Promise<string>` - RSA signing
- `rsaSign64(message: string, privateKey: string, hash?: string): Promise<string>` - RSA signing (base64)
- `rsaVerify(signature: string, message: string, publicKey: string, hash?: string): Promise<boolean>` - RSA signature verification
- `rsaVerify64(signature: string, message: string, publicKey: string, hash?: string): Promise<boolean>` - RSA signature verification (base64)

### Utilities

- `calculateFileChecksum(filePath: string): Promise<string>` - Calculate file checksum

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
