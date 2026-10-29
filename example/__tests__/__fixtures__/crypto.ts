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
  { algorithm: 'SHA1', byteLength: 16, expected: 'boi-i61-rp2eEKoGEiQDTw' },
  {
    algorithm: 'SHA224',
    byteLength: 24,
    expected: '07zzIP2RiQjq_KpGD69A4gH2UI1Obz2c',
  },
  {
    algorithm: 'SHA256',
    byteLength: 32,
    expected: 'YywoEuRtRgQQK6dhjp1tfS-BKPYma0oDJk0qBGC33LM',
  },
  {
    algorithm: 'SHA384',
    byteLength: 32,
    expected: 'O9N-IjaUHUp3sbW3FMb5E_q7awhBptfYZWuZ1hHpAP4',
  },
  {
    algorithm: 'SHA512',
    byteLength: 32,
    expected: 'r-bFUweFtsxrHGRTOEcxvV7kMu5Un9QvtmlXea2KHFs',
  },
] as const;

export const rfc6070Pbkdf2Vector = 'DGDID5YfDnHzqbUkr2ASBg';

export const passwordBase64 = 'cGFzc3dvcmQ=';
export const saltBase64 = 'c2FsdA==';

export const binaryPbkdf2Vector = {
  passwordBase64: 'cGFzcwB3b3Jk',
  saltBase64: 'c2EAbHQ=',
  expected: 'ibadBRb4KYk8aWImZQqGhw',
};

export const latin1Pbkdf2Vector = {
  passwordBase64: 'c2VuaGEg5+Nv',
  expected: 'qohsau2nUpvZso24aCjkf_kTV0InOfqRyy9lmFxKtJM',
};

export const unicodePbkdf2Vector =
  'tmMsm4d1sc7Lp2Uw0IZ2rD5_k-ezSecwRbAby8fmZ44';

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
    key: 'AAECAwQFBgcICQoLDA0ODw',
    plaintext: 'Hello World',
    ivAndCiphertext: '/ty6mHZUMhD+3LqYdlQyEOnPR1E4M1h15nFwEWSQCzY=',
  },
  {
    bits: 192,
    key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYX',
    plaintext: 'Hello World',
    ivAndCiphertext: '/ty6mHZUMhD+3LqYdlQyEC+cpHaJm0ZFvDcZ4Eb7r2k=',
  },
  {
    bits: 256,
    key: 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8',
    plaintext: 'Hello World',
    ivAndCiphertext: '/ty6mHZUMhD+3LqYdlQyEM+WSbej8fGGWDDETqcS0bw=',
  },
];

export const gcmVectors = [
  {
    name: 'NIST zero-key vector',
    key: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    iv: 'AAAAAAAAAAAAAAAA',
    plaintext: '\0'.repeat(16),
    ciphertext: 'zqdAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRk=',
    tamperedCiphertext: 'z6dAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRk=',
    tamperedTag: 'zqdAPU1ga24HTsXTuvOdGNDRyKeZmWvwJluYtdSKuRg=',
  },
  {
    name: 'UTF-8 vector',
    key: 'ASNFZ4mrze8BI0VniavN7wEjRWeJq83vASNFZ4mrze8',
    iv: '/ty6mHZUMhD+3LqY',
    plaintext: unicodeVector.text,
    ciphertext: 'gMAoyVojTQcl91A2ld1ZbbXghQIyFfo23dnjqUV9y+VuHgtrDw+P1+w=',
    tamperedCiphertext:
      'gcAoyVojTQcl91A2ld1ZbbXghQIyFfo23dnjqUV9y+VuHgtrDw+P1+w=',
    tamperedTag: 'gMAoyVojTQcl91A2ld1ZbbXghQIyFfo23dnjqUV9y+VuHgtrDw+P1+0=',
  },
  {
    name: '128-bit key vector',
    key: 'AAECAwQFBgcICQoLDA0ODw',
    iv: '/ty6mHZUMhD+3LqY',
    plaintext: 'Hello World',
    ciphertext: 'kVK5PMpu9kw8ovHb0SllMhYNRxkjCApFsH70',
    tamperedCiphertext: 'kFK5PMpu9kw8ovHb0SllMhYNRxkjCApFsH70',
    tamperedTag: 'kVK5PMpu9kw8ovHb0SllMhYNRxkjCApFsH71',
  },
];

export const zeroKey = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

export const emptyPlaintextVectors = {
  gcmCiphertext: 'Uw+K+8dFNrmpY7TxxMtziw==',
  gcmIv: 'AAAAAAAAAAAAAAAA',
  cbcIvAndCiphertext: 'AAAAAAAAAAAAAAAAAAAAAB94j+bYbDF1SWl/vwwH+kM=',
};

export const invalidUtf8Vectors = {
  gcmCiphertext: 'zqY/vbOfZFVRFhz0XrUaPbeb3TjgeA==',
  gcmIv: 'AAAAAAAAAAAAAAAA',
  cbcIvAndCiphertext: 'AAAAAAAAAAAAAAAAAAAAAPrpEOIj3wVvQWhEZNMISak=',
};

export const fileVector = {
  key: 'YD3rEBXKcb4rc67whX13gR81LAc7YQjXLZgQowkU3_Q',
  iv: '8PHy8/T19vf4+fr7/P3+/w==',
  plaintext:
    'a8G+4i5An5bpPX4Rc5MXKq4tilceA6ycnrdvrEWvjlEwyBxGo1zkEeX7wRkaClLv9p8kRd9PmxetK0F75mw3EA==',
  ciphertext:
    'YB7DE3dXiaW3p/UEu/PSKPRD48pNYrWayoTpkMrK9cUrCTDaoj3pTOhwF7othJiN38nFjbZ6raYTwt0IRXlBpg==',
  sha256: 'd1960c02a724b54ba53df3e4e6ae97b8d72b874e4007839aaf37bf8112067b9a',
  largeSha256:
    'f48e09796d08b5a636390ce7aa35a16a283ac5c5d1d1be208bf2dc04151cab0e',
};
