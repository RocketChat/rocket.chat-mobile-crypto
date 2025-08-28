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
