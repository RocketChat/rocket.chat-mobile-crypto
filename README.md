# @rocket.chat/mobile-crypto

Native cryptography for React Native: SHA, HMAC, PBKDF2, AES-GCM, AES-CBC,
AES-CTR file encryption, RSA-OAEP, RSA signatures and secure random values.

Inputs are taken in the form an app already holds and outputs are returned in
the form it needs next. Wire data is a base64 string, plaintext is a UTF-8
string, and keys live in native memory behind key objects.

## Installation

```sh
npm install @rocket.chat/mobile-crypto react-native-nitro-modules
```

The native module is built with [Nitro Modules](https://nitro.margelo.com), so `react-native-nitro-modules` must be installed alongside it (React Native 0.75+).

On iOS, the crypto code ships in a second pod, `MobileCryptoCore`, that autolinking does not add. Declare it in your app target in `ios/Podfile`, then run `pod install`:

```ruby
target 'YourApp' do
  config = use_native_modules!

  pod 'MobileCryptoCore', :path => '../node_modules/@rocket.chat/mobile-crypto'
  # ...
end
```

## Encodings

- **base64**: standard alphabet with padding. Used for ciphertexts, IVs and signatures on the wire.
- **base64url**: URL-safe alphabet. Output has no padding; input is accepted with or without it. Used for AES keys (the JWK `k` format) and JWK components.
- **UTF-8**: every plaintext string.
- **hex**: only the file SHA-256, in lowercase.

Every failure throws or rejects. No function resolves `null` or `undefined`.

## Usage

### Hashing and HMAC

```ts
import { hmac256, sha } from '@rocket.chat/mobile-crypto';

const digest = await sha(bytes, 'SHA-256'); // ArrayBuffer
const authenticationCode = await hmac256(bytes, keyBytes); // ArrayBuffer
```

### AES keys

```ts
import {
  aesDeriveKey,
  aesGenerateKey,
  aesImportKey,
} from '@rocket.chat/mobile-crypto';

const generated = aesGenerateKey(32); // 16, 24 or 32 bytes
const imported = aesImportKey(jwk.k); // base64url
const derived = await aesDeriveKey(
  passwordBase64,
  saltBase64,
  1000,
  32,
  'SHA256'
);

const k = generated.exportBase64Url();
```

`aesDeriveKey` runs PBKDF2-HMAC over the base64-decoded password and salt bytes, so the caller
chooses how the password text becomes bytes (for example UTF-8 or Latin-1).

### AES-GCM

```ts
import { aesGcmDecrypt, aesGcmEncrypt } from '@rocket.chat/mobile-crypto';

const { iv, ciphertext } = await aesGcmEncrypt(key, 'Hello');
const plaintext = await aesGcmDecrypt(key, ciphertext, iv);
```

Each call generates a fresh 12-byte IV. `ciphertext` ends with the 16-byte
authentication tag. Decryption rejects on a wrong key, a modified ciphertext
or tag, invalid base64, or plaintext that is not valid UTF-8.

### AES-CBC

```ts
import { aesCbcDecrypt, aesCbcEncrypt } from '@rocket.chat/mobile-crypto';

const ivAndCiphertext = await aesCbcEncrypt(key, 'Hello');
const plaintext = await aesCbcDecrypt(key, ivAndCiphertext);
```

Each call generates a fresh 16-byte IV and returns `base64(iv ‖ ciphertext)`
with PKCS#7 padding.

### Files

```ts
import { aesDecryptFile, aesEncryptFile } from '@rocket.chat/mobile-crypto';

const { path, key, iv, sha256 } = await aesEncryptFile('file:///path/to/file');
const decryptedPath = await aesDecryptFile(path, key, iv, sha256);
```

`aesEncryptFile` encrypts a copy of the file with AES-256-CTR under a fresh
key and IV and returns the SHA-256 of the original. `aesDecryptFile` decrypts
in place and checks the SHA-256 of the result (case-insensitively); on a
mismatch it removes the decrypted output and rejects.

### RSA

```ts
import {
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
} from '@rocket.chat/mobile-crypto';

const { publicKey, privateKey } = await rsaGenerateKeys(2048);
const storedPrivateKey = privateKey.exportJwk(); // JWK JSON string

const restoredPrivateKey = await rsaImportPrivateKey(storedPrivateKey);
const restoredPublicKey = await rsaImportPublicKey(publicJwkJson);

const ciphertext = await restoredPublicKey.encrypt('Hello'); // base64, RSA-OAEP SHA-256
const plaintext = await restoredPrivateKey.decrypt(ciphertext);

const signature = await restoredPrivateKey.sign(messageBytes, 'SHA256');
const isValid = await restoredPublicKey.verify(
  signature,
  messageBytes,
  'SHA256'
);
```

`exportJwk()` returns compact JSON with the fields in the order `kty, alg,
ext, key_ops, n, e, d, p, q, dp, dq, qi`, using `alg: "RSA-OAEP-256"`,
`ext: true` and `key_ops: ["encrypt"]` or `["decrypt"]`.
`rsaImportPublicKey` ignores private fields, so it accepts a private JWK too.

### Random values

```ts
import { randomBytes, randomKey, randomUuid } from '@rocket.chat/mobile-crypto';

const uuid = randomUuid(); // version 4 UUID
const keyHex = randomKey(16); // 16 bytes as lowercase hex
const bytes = randomBytes(32); // ArrayBuffer
```

## API reference

### Hashing

- `sha(data: ArrayBuffer, algorithm: SHAAlgorithm): Promise<ArrayBuffer>`
- `hmac256(data: ArrayBuffer, key: ArrayBuffer): Promise<ArrayBuffer>` - HMAC-SHA256

`SHAAlgorithm` is `'SHA-1' | 'SHA-256' | 'SHA-384' | 'SHA-512'`.

### AES

- `aesGenerateKey(byteLength: number): AESKey`
- `aesImportKey(base64Url: string): AESKey`
- `aesDeriveKey(passwordBase64: string, saltBase64: string, iterations: number, byteLength: number, hash: PBKDF2HashAlgorithm): Promise<AESKey>`
- `AESKey.exportBase64Url(): string`
- `aesGcmEncrypt(key: AESKey, plaintext: string): Promise<{ iv: string; ciphertext: string }>`
- `aesGcmDecrypt(key: AESKey, ciphertext: string, iv: string): Promise<string>`
- `aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string>`
- `aesCbcDecrypt(key: AESKey, ivAndCiphertext: string): Promise<string>`
- `aesEncryptFile(filePath: string): Promise<{ path: string; key: string; iv: string; sha256: string }>`
- `aesDecryptFile(filePath: string, key: string, iv: string, sha256: string): Promise<string>`

`PBKDF2HashAlgorithm` is `'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512'`.

### RSA

- `rsaGenerateKeys(keySize = 2048): Promise<{ publicKey: RSAPublicKey; privateKey: RSAPrivateKey }>`
- `rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey>`
- `rsaImportPublicKey(jwk: string): Promise<RSAPublicKey>`
- `RSAPrivateKey.decrypt(ciphertext: string): Promise<string>`
- `RSAPrivateKey.sign(message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>` - PKCS#1 v1.5
- `RSAPrivateKey.exportJwk(): string`
- `RSAPublicKey.encrypt(plaintext: string): Promise<string>`
- `RSAPublicKey.verify(signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<boolean>`
- `RSAPublicKey.exportJwk(): string`

`RSAHashAlgorithm` is `'Raw' | 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512'`. `Raw` signs the message as an already computed digest.

### Random

- `randomUuid(): string`
- `randomKey(length: number): string` - `length` bytes as lowercase hex
- `randomBytes(size: number): ArrayBuffer`

## Migrating from v1

v2 removes every v1 string and buffer variant. Keys are imported once into key
objects, IVs are generated by the library, PEM is gone in favour of JWK JSON,
and failures reject instead of resolving `null`.

| v1                                                                                        | v2                                                                                                                |
| ----------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `shaUtf8(text, algorithm)`, `shaBase64(base64, algorithm)`, `shaBuffer(bytes, algorithm)` | `sha(bytes, algorithm)`, returning an `ArrayBuffer`                                                               |
| `hmac256(dataHex, keyHex)`, `hmac256Buffer(data, key)`                                    | `hmac256(data, key)` on `ArrayBuffer`s                                                                            |
| `pbkdf2Hash(passwordBase64, saltBase64, iterations, keyLength, hash)`                     | `aesDeriveKey(passwordBase64, saltBase64, iterations, byteLength, hash)`; read the bytes with `exportBase64Url()` |
| `aesGcmEncrypt(dataBase64, keyHex, ivHex)`, `aesGcmEncryptBuffer`                         | `aesGcmEncrypt(key, plaintext)`, returning `{ iv, ciphertext }`                                                   |
| `aesGcmDecrypt(dataBase64, keyHex, ivHex)`, `aesGcmDecryptBuffer`                         | `aesGcmDecrypt(key, ciphertext, iv)`, returning UTF-8                                                             |
| `aesEncrypt(dataBase64, keyHex, ivHex)`, `aesEncryptBuffer` (AES-CBC)                     | `aesCbcEncrypt(key, plaintext)`, returning `base64(iv ‖ ciphertext)`                                              |
| `aesDecrypt(dataBase64, keyHex, ivHex)`, `aesDecryptBuffer` (AES-CBC)                     | `aesCbcDecrypt(key, ivAndCiphertext)`                                                                             |
| `aesEncryptFile(path, key, iv)`                                                           | `aesEncryptFile(path)`, returning `{ path, key, iv, sha256 }`                                                     |
| `aesDecryptFile(path, key, iv)`                                                           | `aesDecryptFile(path, key, iv, sha256)`                                                                           |
| `calculateFileChecksum(path)`                                                             | the `sha256` returned by `aesEncryptFile`, verified by `aesDecryptFile`                                           |
| `rsaGenerateKeys()` returning PEM `{ public, private }`                                   | `rsaGenerateKeys()` returning `{ publicKey, privateKey }` key objects; persist them with `exportJwk()`            |
| `rsaImportPrivateKey(pem)`, `rsaImportPublicKey(pem)`                                     | the same functions, taking a JWK JSON string                                                                      |
| `rsaImportKey(jwk)` (JWK to PEM), `rsaExportKey(pem)`, `rsaPemToJwk(pem)`                 | `rsaImportPrivateKey(jwkJson)` / `rsaImportPublicKey(jwkJson)` and `exportJwk()`                                  |
| `rsaEncrypt(text, publicKeyPem)`, `rsaEncrypt64`                                          | `publicKey.encrypt(text)`                                                                                         |
| `rsaDecrypt(ciphertext, privateKeyPem)`, `rsaDecrypt64`                                   | `privateKey.decrypt(ciphertext)`, returning UTF-8                                                                 |
| `rsaSign(message, privateKeyPem, hash)`, `rsaSign64`                                      | `privateKey.sign(messageBytes, hash)`, returning an `ArrayBuffer`                                                 |
| `rsaVerify(signature, message, publicKeyPem, hash)`, `rsaVerify64`                        | `publicKey.verify(signatureBytes, messageBytes, hash)`                                                            |
| `randomBytes(size)` (base64), `randomBytesBuffer(size)`                                   | `randomBytes(size)`, returning an `ArrayBuffer`                                                                   |
| `randomUuid()`, `randomKey(length)`                                                       | unchanged values, now returned synchronously                                                                      |
| `getRandomValues(length)`                                                                 | removed                                                                                                           |
| `JWK` type                                                                                | JWK JSON strings                                                                                                  |

Deterministic outputs are byte-compatible with v1: the same password, salt
and parameters derive the same key bytes, RSA signatures and JWK components
are unchanged, and UTF-8 text encrypted by v1 decrypts with v2 (for AES-CBC, prefix
the IV to the ciphertext).

## Contributing

- [Development workflow](CONTRIBUTING.md#development-workflow)
- [Sending a pull request](CONTRIBUTING.md#sending-a-pull-request)
- [Code of conduct](CODE_OF_CONDUCT.md)

## License

MIT

---

Made with [create-react-native-library](https://github.com/callstack/react-native-builder-bob)
