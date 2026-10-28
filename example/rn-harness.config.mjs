import {
  androidEmulator,
  androidPlatform,
} from '@react-native-harness/platform-android';
import {
  applePlatform,
  appleSimulator,
} from '@react-native-harness/platform-apple';

export default {
  entryPoint: './index.js',
  appRegistryComponentName: 'MobileCryptoExample',
  testTimeout: 600000,
  metroPort: Number(process.env.HARNESS_METRO_PORT || 8081),
  resetEnvironmentBetweenTestFiles: process.env.HARNESS_RESET_MODE || 'runtime',
  cache: {
    version: process.env.HARNESS_CACHE_VERSION || undefined,
  },
  runners: [
    applePlatform({
      name: 'ios',
      device: appleSimulator(
        process.env.HARNESS_IOS_DEVICE || 'Mobile Crypto Harness',
        process.env.HARNESS_IOS_VERSION || '27.0'
      ),
      bundleId: 'rocketchat.mobilecrypto.example',
    }),
    androidPlatform({
      name: 'android',
      device: androidEmulator(
        process.env.HARNESS_ANDROID_DEVICE || 'Pixel_API_34_arm64'
      ),
      bundleId: 'rocketchat.mobilecrypto.example',
    }),
  ],
  defaultRunner: 'ios',
};
