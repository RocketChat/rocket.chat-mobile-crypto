import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  multiply(a: number, b: number): number;
  shaBase64(data: string, algorithm: string): Promise<string>;
  shaUtf8(data: string, algorithm: string): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('MobileCrypto');
