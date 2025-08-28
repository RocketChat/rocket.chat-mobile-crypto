import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  multiply(a: number, b: number): number;
  shaBase64(data: string, algorithm: string): Promise<string>;
  shaUtf8(data: string, algorithm: string): Promise<string>;
  pbkdf2Hash(
    pwdBase64: string,
    saltBase64: string,
    iterations: number,
    keyLen: number,
    hash: string
  ): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('MobileCrypto');
