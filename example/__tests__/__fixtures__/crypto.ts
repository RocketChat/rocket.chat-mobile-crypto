// Fixed answers generated independently with Node.js node:crypto (OpenSSL).
// File encryption uses NIST SP 800-38A F.5.5; HMAC uses RFC 4231.
// No expected values are calculated by the library under test.

export const hashVectors = [
  {
    algorithm: 'SHA-1',
    hex: 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',
    base64: 'qvTGHdzF6KLavt4PO0gs2a6pQ00=',
  },
  {
    algorithm: 'SHA-256',
    hex: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824',
    base64: 'LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=',
  },
  {
    algorithm: 'SHA-384',
    hex: '59e1748777448c69de6b800d7a33bbfb9ff1b463e44354c3553bcdb9c666fa90125a3c79f90397bdf5f6a13de828684f',
    base64: 'WeF0h3dEjGnea4ANejO7+5/xtGPkQ1TDVTvNucZm+pASWjx5+QOXvfX2oT3oKGhP',
  },
  {
    algorithm: 'SHA-512',
    hex: '9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043',
    base64:
      'm3HSJL1i83hdltRq0+o9czGb+8KJDKra4t/3JRlnPKcjI8PZm6XBHXx6zG4UuMXaDEZjR1wuXDre9G9zvN7AQw==',
  },
] as const;

export const unicodeVector = {
  text: 'Rocket.Chat 🔐 — olá',
  base64: 'Um9ja2V0LkNoYXQg8J+UkCDigJQgb2zDoQ==',
  hex: '43d3fe2fd48b08317cfc7b4259d24849e22656e184a9a55ca2bfba9198faab10',
  digestBase64: 'Q9P+L9SLCDF8/HtCWdJISeImVuGEqaVcor+6kZj6qxA=',
};

export const binaryHashVector = {
  base64: 'AAF/gP7/',
  digestBase64: 'odh0jQ2+DJ9PZ2k0bnsU+MV8vWNu9A3UCiG5bX54qjk=',
};

export const pbkdf2Vectors = [
  {
    algorithm: 'SHA1',
    keyLength: 20,
    expected: 'boi+i61+rp2eEKoGEiQDT+1I0D8=',
  },
  {
    algorithm: 'SHA224',
    keyLength: 28,
    expected: '07zzIP2RiQjq/KpGD69A4gH2UI1Obz2cHAq9MA==',
  },
  {
    algorithm: 'SHA256',
    keyLength: 32,
    expected: 'YywoEuRtRgQQK6dhjp1tfS+BKPYma0oDJk0qBGC33LM=',
  },
  {
    algorithm: 'SHA384',
    keyLength: 48,
    expected:
      'O9N+IjaUHUp3sbW3FMb5E/q7awhBptfYZWuZ1hHpAP4G7bk7W4Ce+qlni2Nc5RPg',
  },
  {
    algorithm: 'SHA512',
    keyLength: 64,
    expected:
      'r+bFUweFtsxrHGRTOEcxvV7kMu5Un9QvtmlXea2KHFv1neacSPd078QAfVKY+QM8AkHVq2kwXntk7O642DTP7A==',
  },
] as const;

export const binaryPbkdf2Vector = {
  password: 'cGFzcwB3b3Jk',
  salt: 'c2EAbHQ=',
  expected: 'ibadBRb4KYk8aWImZQqGhw==',
};

export const hmacVectors = [
  {
    name: 'RFC 4231 case 1',
    dataHex: '4869205468657265',
    keyHex: '0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b',
    expected:
      'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7',
  },
  {
    name: 'RFC 4231 case 2',
    dataHex: '7768617420646f2079612077616e7420666f72206e6f7468696e673f',
    keyHex: '4a656665',
    expected:
      '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843',
  },
  {
    name: 'RFC 4231 case 6 (key longer than the block size)',
    dataHex:
      '54657374205573696e67204c6172676572205468616e20426c6f636b2d53697a65204b6579202d2048617368204b6579204669727374',
    keyHex:
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    expected:
      '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54',
  },
];

export const cbcVectors = [
  {
    bits: 128,
    keyHex: '000102030405060708090a0b0c0d0e0f',
    ivHex: 'fedcba9876543210fedcba9876543210',
    plaintext: 'SGVsbG8gV29ybGQ=',
    ciphertext: '6c9HUTgzWHXmcXARZJALNg==',
  },
  {
    bits: 192,
    keyHex: '000102030405060708090a0b0c0d0e0f1011121314151617',
    ivHex: 'fedcba9876543210fedcba9876543210',
    plaintext: 'SGVsbG8gV29ybGQ=',
    ciphertext: 'L5ykdombRkW8NxngRvuvaQ==',
  },
  {
    bits: 256,
    keyHex: '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    ivHex: 'fedcba9876543210fedcba9876543210',
    plaintext: 'SGVsbG8gV29ybGQ=',
    ciphertext: 'z5ZJt6Px8YZYMMROpxLRvA==',
  },
];

export const gcmVectors = [
  {
    name: 'NIST zero-key vector',
    keyHex: '0000000000000000000000000000000000000000000000000000000000000000',
    ivHex: '000000000000000000000000',
    plaintext: 'AAAAAAAAAAAAAAAAAAAAAA==',
    ciphertext: 'zqdAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRk=',
    tamperedCiphertext: 'z6dAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRk=',
    tamperedTag: 'zqdAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRg=',
  },
  {
    name: 'UTF-8 vector',
    keyHex: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    ivHex: 'fedcba9876543210fedcba98',
    plaintext: 'Um9ja2V0LkNoYXQg8J+UkCDigJQgb2zDoQ==',
    ciphertext: 'gMAoyVojTQcl91A2ld1ZbbXghQIyFfo23dnjqUV9y+VuHgtrDw+P1+w=',
    tamperedCiphertext:
      'gcAoyVojTQcl91A2ld1ZbbXghQIyFfo23dnjqUV9y+VuHgtrDw+P1+w=',
    tamperedTag: 'gMAoyVojTQcl91A2ld1ZbbXghQIyFfo23dnjqUV9y+VuHgtrDw+P1+0=',
  },
];

export const fileVector = {
  key: 'YD3rEBXKcb4rc67whX13gR81LAc7YQjXLZgQowkU3_Q',
  iv: '8PHy8/T19vf4+fr7/P3+/w==',
  plaintext:
    'a8G+4i5An5bpPX4Rc5MXKq4tilceA6ycnrdvrEWvjlEwyBxGo1zkEeX7wRkaClLv9p8kRd9PmxetK0F75mw3EA==',
  ciphertext:
    'YB7DE3dXiaW3p/UEu/PSKPRD48pNYrWayoTpkMrK9cUrCTDaoj3pTOhwF7othJiN38nFjbZ6raYTwt0IRXlBpg==',
  checksum: 'd1960c02a724b54ba53df3e4e6ae97b8d72b874e4007839aaf37bf8112067b9a',
  largeChecksum:
    'f48e09796d08b5a636390ce7aa35a16a283ac5c5d1d1be208bf2dc04151cab0e',
};
