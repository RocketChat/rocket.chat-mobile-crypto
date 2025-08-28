import MobileCrypto from './NativeMobileCrypto';

export function multiply(a: number, b: number): number {
  return MobileCrypto.multiply(a, b);
}

export function shaBase64(data: string, algorithm: string): Promise<string> {
  return MobileCrypto.shaBase64(data, algorithm);
}

export function shaUtf8(data: string, algorithm: string): Promise<string> {
  return MobileCrypto.shaUtf8(data, algorithm);
}

export function pbkdf2Hash(
  pwdBase64: string,
  saltBase64: string,
  iterations: number,
  keyLen: number,
  hash: string
): Promise<string> {
  return MobileCrypto.pbkdf2Hash(
    pwdBase64,
    saltBase64,
    iterations,
    keyLen,
    hash
  );
}

export function hmac256(data: string, key: string): Promise<string> {
  return MobileCrypto.hmac256(data, key);
}
