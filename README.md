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

- **base64**: standard alphabet with padding. Used for ciphertexts and IVs on the wire.
- **base64url**: URL-safe alphabet. Output has no padding; input is accepted with or without it. Used for AES keys (the JWK `k` format) and JWK components.
- **UTF-8**: every plaintext string. Decrypted text keeps a leading byte order mark (U+FEFF).
- **hex**: the file SHA-256 and `randomKey` output, in lowercase.

Encoded input is decoded strictly, the same way on iOS and Android. It is
rejected when it contains whitespace or line breaks, uses the other base64
alphabet, has wrong padding (base64 must be padded; base64url may omit it), or
does not re-encode to the same text.

## Errors

A function that returns a `Promise` rejects on failure and never throws. A
function that returns a value directly (`aesGenerateKey`, `aesImportKey`,
`exportBase64Url`, `exportJwk`, `randomUuid`, `randomKey`, `randomBytes`)
throws. No function returns or resolves `null` or `undefined`.

## Known issues

On Android, a string argument passed from JavaScript stops at its first NUL
character (`\0`); the rest is dropped without an error. iOS keeps the whole
string. Rocket.Chat inputs can't contain a raw NUL (base64, file paths, JSON),
but arbitrary text passed to `aesGcmEncrypt`, `aesCbcEncrypt` or
`rsaEncrypt` would be encrypted truncated on Android. Tracked in
[NATIVE-1874](https://rocketchat.atlassian.net/browse/NATIVE-1874).

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

const generated = aesGenerateKey(32); // 16 or 32 bytes
const imported = aesImportKey(jwk.k); // base64url
const derived = await aesDeriveKey(passwordBase64, saltBase64, {
  iterations: 1000,
  byteLength: 32,
  hash: 'SHA256',
});

const k = generated.exportBase64Url();
```

`aesDeriveKey` runs PBKDF2-HMAC over the base64-decoded password and salt bytes, so the caller
chooses how the password text becomes bytes (for example UTF-8 or Latin-1).

### AES-GCM

```ts
import { aesGcmDecrypt, aesGcmEncrypt } from '@rocket.chat/mobile-crypto';

const encrypted = await aesGcmEncrypt(key, 'Hello'); // { iv, ciphertext }
const plaintext = await aesGcmDecrypt(key, encrypted);
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
with PKCS#7 padding. Decryption rejects padding that is not valid PKCS#7,
invalid base64, or plaintext that is not valid UTF-8. CBC has no
authentication tag, so a wrong key is caught only when it breaks the padding
or the UTF-8.

### Files

```ts
import { aesDecryptFile, aesEncryptFile } from '@rocket.chat/mobile-crypto';

const encryptedFile = await aesEncryptFile('file:///path/to/file'); // { path, key, iv, sha256 }
const decryptedPath = await aesDecryptFile(encryptedFile);
```

`aesEncryptFile` encrypts a copy of the file with AES-256-CTR under a fresh
key and IV and returns the SHA-256 of the original. `aesDecryptFile` decrypts
in place and checks the SHA-256 of the result (case-insensitively); on a
mismatch it removes the decrypted output and rejects.

### RSA

```ts
import {
  rsaDecrypt,
  rsaEncrypt,
  rsaGenerateKeys,
  rsaImportPrivateKey,
  rsaImportPublicKey,
  rsaSign,
  rsaVerify,
} from '@rocket.chat/mobile-crypto';

const { publicKey, privateKey } = await rsaGenerateKeys(2048);
const storedPrivateKey = privateKey.exportJwk(); // JWK JSON string

const restoredPrivateKey = await rsaImportPrivateKey(storedPrivateKey);
const restoredPublicKey = await rsaImportPublicKey(publicJwkJson);

const ciphertext = await rsaEncrypt(restoredPublicKey, 'Hello'); // base64, RSA-OAEP SHA-256
const plaintext = await rsaDecrypt(restoredPrivateKey, ciphertext);

const signature = await rsaSign(restoredPrivateKey, messageBytes, 'SHA256');
const isValid = await rsaVerify(
  restoredPublicKey,
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
- `aesDeriveKey(passwordBase64: string, saltBase64: string, options: { iterations: number; byteLength: number; hash: PBKDF2HashAlgorithm }): Promise<AESKey>` - `byteLength` must be 16 or 32
- `AESKey.exportBase64Url(): string`
- `aesGcmEncrypt(key: AESKey, plaintext: string): Promise<AESGCMCiphertext>`
- `aesGcmDecrypt(key: AESKey, encrypted: AESGCMCiphertext): Promise<string>`
- `aesCbcEncrypt(key: AESKey, plaintext: string): Promise<string>`
- `aesCbcDecrypt(key: AESKey, ivAndCiphertext: string): Promise<string>`
- `aesEncryptFile(filePath: string): Promise<EncryptedFile>`
- `aesDecryptFile(file: EncryptedFile): Promise<string>`

`AESGCMCiphertext` is `{ iv: string; ciphertext: string }`, both base64.
`EncryptedFile` is `{ path: string; key: string; iv: string; sha256: string }`:
the key in base64url, the IV in base64 and the SHA-256 of the plaintext in hex.
All four fields are required; build it from an E2E attachment's `encryption`
and `hashes.sha256` to decrypt a received file.

`PBKDF2HashAlgorithm` is `'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512'`.

### RSA

- `rsaGenerateKeys(keySize = 2048): Promise<RSAKeyPair>` - `RSAKeyPair` is `{ publicKey: RSAPublicKey; privateKey: RSAPrivateKey }`
- `rsaImportPrivateKey(jwk: string): Promise<RSAPrivateKey>`
- `rsaImportPublicKey(jwk: string): Promise<RSAPublicKey>`
- `RSAPrivateKey.exportJwk(): string`
- `RSAPublicKey.exportJwk(): string`
- `rsaEncrypt(publicKey: RSAPublicKey, plaintext: string): Promise<string>`
- `rsaDecrypt(privateKey: RSAPrivateKey, ciphertext: string): Promise<string>`
- `rsaSign(privateKey: RSAPrivateKey, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<ArrayBuffer>` - PKCS#1 v1.5
- `rsaVerify(publicKey: RSAPublicKey, signature: ArrayBuffer, message: ArrayBuffer, hash: RSAHashAlgorithm): Promise<boolean>`

`RSAHashAlgorithm` is `'Raw' | 'SHA1' | 'SHA224' | 'SHA256' | 'SHA384' | 'SHA512'`. `Raw` signs the message as an already computed digest.

### Random

- `randomUuid(): string`
- `randomKey(length: number): string` - `length` bytes as lowercase hex
- `randomBytes(size: number): ArrayBuffer`

## Migrating from v1

v2 removes every v1 string and buffer variant. Keys are imported once into key
objects, IVs are generated by the library, PEM is gone in favour of JWK JSON,
and failures reject or throw instead of resolving `null`.

| v1                                                                                        | v2                                                                                                                                           |
| ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `shaUtf8(text, algorithm)`, `shaBase64(base64, algorithm)`, `shaBuffer(bytes, algorithm)` | `sha(bytes, algorithm)`, returning an `ArrayBuffer`                                                                                          |
| `hmac256(dataHex, keyHex)`, `hmac256Buffer(data, key)`                                    | `hmac256(data, key)` on `ArrayBuffer`s                                                                                                       |
| `pbkdf2Hash(passwordBase64, saltBase64, iterations, keyLength, hash)`                     | `aesDeriveKey(passwordBase64, saltBase64, { iterations, byteLength, hash })` with `byteLength` 16 or 32; read the bytes with `exportBase64Url()` |
| `aesGcmEncrypt(dataBase64, keyHex, ivHex)`, `aesGcmEncryptBuffer`                         | `aesGcmEncrypt(key, plaintext)`, returning `{ iv, ciphertext }`                                                                              |
| `aesGcmDecrypt(dataBase64, keyHex, ivHex)`, `aesGcmDecryptBuffer`                         | `aesGcmDecrypt(key, { iv, ciphertext })`, returning UTF-8                                                                                    |
| `aesEncrypt(dataBase64, keyHex, ivHex)`, `aesEncryptBuffer` (AES-CBC)                     | `aesCbcEncrypt(key, plaintext)`, returning `base64(iv ‖ ciphertext)`                                                                         |
| `aesDecrypt(dataBase64, keyHex, ivHex)`, `aesDecryptBuffer` (AES-CBC)                     | `aesCbcDecrypt(key, ivAndCiphertext)`                                                                                                        |
| `aesEncryptFile(path, key, iv)`                                                           | `aesEncryptFile(path)`, returning `{ path, key, iv, sha256 }`                                                                                |
| `aesDecryptFile(path, key, iv)`                                                           | `aesDecryptFile({ path, key, iv, sha256 })`                                                                                                  |
| `calculateFileChecksum(path)`                                                             | the `sha256` returned by `aesEncryptFile`, verified by `aesDecryptFile`                                                                      |
| `rsaGenerateKeys()` returning PEM `{ public, private }`                                   | `rsaGenerateKeys()` returning `{ publicKey, privateKey }` key objects; persist them with `exportJwk()`                                       |
| `rsaImportKey(jwk)` (JWK to PEM), `rsaExportKey(pem)`, `rsaPemToJwk(pem)`                 | `rsaImportPrivateKey(jwkJson)` / `rsaImportPublicKey(jwkJson)` and `exportJwk()`                                                             |
| `rsaEncrypt(text, publicKeyPem)`, `rsaEncrypt64`                                          | `rsaEncrypt(publicKey, text)`                                                                                                                |
| `rsaDecrypt(ciphertext, privateKeyPem)`, `rsaDecrypt64`                                   | `rsaDecrypt(privateKey, ciphertext)`, returning UTF-8                                                                                        |
| `rsaSign(message, privateKeyPem, hash)`, `rsaSign64`                                      | `rsaSign(privateKey, messageBytes, hash)`, returning an `ArrayBuffer`                                                                        |
| `rsaVerify(signature, message, publicKeyPem, hash)`, `rsaVerify64`                        | `rsaVerify(publicKey, signatureBytes, messageBytes, hash)`                                                                                   |
| `randomBytes(size)` (base64), `randomBytesBuffer(size)`                                   | `randomBytes(size)`, returning an `ArrayBuffer` synchronously                                                                                |
| `randomUuid()`, `randomKey(length)`                                                       | unchanged values, now returned synchronously                                                                                                 |
| `getRandomValues(length)`                                                                 | removed                                                                                                                                      |
| `JWK` type                                                                                | JWK JSON strings                                                                                                                             |

The rows above are not all one-to-one:

- AES and RSA encryption in v2 take and return UTF-8 text only. The v1 `*64`
  and `*Buffer` variants carried arbitrary bytes, and v2 has no binary
  replacement for them.
- v1 `rsaSign` and `rsaVerify` took an optional `hash` that defaulted to SHA-1
  on Android and SHA-512 on iOS. v2 requires it: pass the hash v1 used to get
  the same signatures.
- v1 AES functions took the key as hex. Pass the JWK `k` value to `aesImportKey`
  as it is, without converting it to hex.

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
