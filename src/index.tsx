import MobileCrypto from './NativeMobileCrypto';

export function multiply(a: number, b: number): number {
  return MobileCrypto.multiply(a, b);
}
