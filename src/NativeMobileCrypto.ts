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
  hmac256(data: string, key: string): Promise<string>;
  aesEncrypt(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): Promise<string>;
  aesDecrypt(
    dataBase64: string,
    keyHex: string,
    ivHex: string
  ): Promise<string>;
  aesEncryptFile(
    filePath: string,
    base64UrlKey: string,
    base64Iv: string
  ): Promise<string>;
  aesDecryptFile(
    filePath: string,
    base64UrlKey: string,
    base64Iv: string
  ): Promise<string>;
  randomUuid(): Promise<string>;
  randomKey(length: number): Promise<string>;
  randomBytes(size: number): Promise<string>;
  rsaGenerateKeys(
    keySize?: number
  ): Promise<{ public: string; private: string }>;
  rsaEncrypt(message: string, publicKey: string): Promise<string>;
  rsaEncrypt64(message: string, publicKey: string): Promise<string>;
  rsaDecrypt(encodedMessage: string, privateKey: string): Promise<string>;
  rsaDecrypt64(encodedMessage: string, privateKey: string): Promise<string>;
  rsaSign(message: string, privateKey: string, hash?: string): Promise<string>;
  rsaSign64(
    message: string,
    privateKey: string,
    hash?: string
  ): Promise<string>;
  rsaVerify(
    signature: string,
    message: string,
    publicKey: string,
    hash?: string
  ): Promise<boolean>;
  rsaVerify64(
    signature: string,
    message: string,
    publicKey: string,
    hash?: string
  ): Promise<boolean>;
  calculateFileChecksum(filePath: string): Promise<string>;
  getRandomValues(length: number): Promise<string>;
}

export default TurboModuleRegistry.getEnforcing<Spec>('MobileCrypto');
