# Contributing

Contributions are always welcome, no matter how large or small!

We want this community to be friendly and respectful to each other. Please follow it in all your interactions with the project. Before contributing, please read the [code of conduct](./CODE_OF_CONDUCT.md).

## Development workflow

This project is a monorepo managed using [Yarn workspaces](https://yarnpkg.com/features/workspaces). It contains the following packages:

- The library package in the root directory.
- An example app in the `example/` directory.

To get started with the project, make sure you have the correct version of [Node.js](https://nodejs.org/) installed. See the [`.nvmrc`](./.nvmrc) file for the version used in this project.

Run `yarn` in the root directory to install the required dependencies for each package:

```sh
yarn
```

> Since the project relies on Yarn workspaces, you cannot use [`npm`](https://github.com/npm/cli) for development without manually migrating.

The [example app](/example/) demonstrates usage of the library. You need to run it to test any changes you make.

It is configured to use the local version of the library, so any changes you make to the library's source code will be reflected in the example app. Changes to the library's JavaScript code will be reflected in the example app without a rebuild, but native code changes will require a rebuild of the example app.

If you want to use Android Studio or XCode to edit the native code, you can open the `example/android` or `example/ios` directories respectively in those editors. To edit the Objective-C or Swift files, open `example/ios/MobileCryptoExample.xcworkspace` in XCode and find the source files at `Pods > Development Pods > @rocket.chat/mobile-crypto`.

To edit the Java or Kotlin files, open `example/android` in Android studio and find the source files at `rocket-chat-mobile-crypto` under `Android`.

You can use various commands from the root directory to work with the project.

To start the packager:

```sh
yarn example start
```

To run the example app on Android:

```sh
yarn example android
```

To run the example app on iOS:

```sh
yarn example ios
```

To confirm that the app is running with the new architecture, you can check the Metro logs for a message like this:

```sh
Running "MobileCryptoExample" with {"fabric":true,"initialProps":{"concurrentRoot":true},"rootTag":1}
```

Note the `"fabric":true` and `"concurrentRoot":true` properties.

Make sure your code passes TypeScript and ESLint. Run the following to verify:

```sh
yarn typecheck
yarn lint
```

To fix formatting errors, run the following:

```sh
yarn lint --fix
```

The crypto tests use [React Native Harness](https://www.react-native-harness.dev/) to run against the real native module in the example app. Test files live in `example/__tests__/*.harness.ts` and import their test APIs from `react-native-harness`.

Build and install the example app before running tests. Harness starts its own Metro server, so stop any existing Metro process on the test port first.

For iOS, the default runner uses a simulator named `Mobile Crypto Harness` with iOS 27.0. Create it once if needed:

```sh
xcrun simctl create 'Mobile Crypto Harness' com.apple.CoreSimulator.SimDeviceType.iPhone-18-Pro com.apple.CoreSimulator.SimRuntime.iOS-27-0
```

To use another installed simulator, set its name and runtime version in your shell:

```sh
export HARNESS_IOS_DEVICE='iPhone 17 Pro'
export HARNESS_IOS_VERSION='26.2'
```

Install pods from `example/`, then build and install on the selected simulator:

```sh
(cd example && pod install --project-directory=ios)
yarn example ios --simulator "${HARNESS_IOS_DEVICE:-Mobile Crypto Harness}" --no-packager
```

Start with the smoke suite to check native module access, asynchronous hashing, and UUID generation:

```sh
yarn test:smoke --harnessRunner ios
```

Run the complete suite after the smoke tests pass:

```sh
yarn test --harnessRunner ios
```

The suite covers SHA, PBKDF2, HMAC, AES-CBC, AES-GCM authentication failures, secure random output formats, RSA encryption/signatures, PEM/JWK conversion, file checksums, and AES-CTR file operations. Fixed answers live in `example/__tests__/__fixtures__`; they come from independent crypto vectors rather than the library under test. The public RSA keys and fixed answers live in `example/fixtures/rsa.ts`, shared by the tests and the example app.

File tests use `react-native-file-access` as an example-app development dependency to create and remove real cache files, including binary data, encoded file URIs, empty files, and files spanning multiple native read buffers. Rebuild the example app after changing native dependencies.

An Android runner is also configured. Select an installed AVD and build/install the example app on that emulator before running:

```sh
export HARNESS_ANDROID_DEVICE='Pixel_API_34_arm64'
yarn example android --no-packager
yarn test:smoke --harnessRunner android
yarn test --harnessRunner android
```

Use `HARNESS_METRO_PORT` to select a different port (default `8081`). Harness manages its own Metro process and serializes tests on the selected device. Jest flags such as `--testNamePattern` and `--watch` are supported; `--maxWorkers` and `--runInBand` are not Harness options.

The default `runtime` reset keeps the native app process open across all test files and reloads JavaScript between files to isolate module state, globals, and test hooks. Native state and files survive a JavaScript reload; file tests remove their own temporary files. Harness can still restart the app to recover from a failed reload or test timeout. To check a native-state isolation problem, opt into full process restarts:

```sh
HARNESS_RESET_MODE=process yarn test --harnessRunner ios
```

CI builds and installs the example app on a dedicated iOS simulator and Android emulator before running the same native suite on each. Their device and runtime overrides are defined in `.github/workflows/ci.yml`.

### Commit message convention

We follow the [conventional commits specification](https://www.conventionalcommits.org/en) for our commit messages:

- `fix`: bug fixes, e.g. fix crash due to deprecated method.
- `feat`: new features, e.g. add new method to the module.
- `refactor`: code refactor, e.g. migrate from class components to hooks.
- `docs`: changes into documentation, e.g. add usage example for the module..
- `test`: adding or updating tests, e.g. add integration tests using detox.
- `chore`: tooling changes, e.g. change CI config.

Our pre-commit hooks verify that your commit message matches this format when committing.

### Linting and tests

[ESLint](https://eslint.org/), [Prettier](https://prettier.io/), [TypeScript](https://www.typescriptlang.org/)

We use [TypeScript](https://www.typescriptlang.org/) for type checking, [ESLint](https://eslint.org/) with [Prettier](https://prettier.io/) for linting and formatting the code, and React Native Harness for native integration tests.

Our pre-commit hooks verify that the linter and tests pass when committing.

### Publishing to npm

We use [release-it](https://github.com/release-it/release-it) to make it easier to publish new versions. It handles common tasks like bumping version based on semver, creating tags and releases etc.

To publish new versions, run the following:

```sh
yarn release
```

### Scripts

The `package.json` file contains various scripts for common tasks:

- `yarn`: setup project by installing dependencies.
- `yarn typecheck`: type-check files with TypeScript.
- `yarn lint`: lint files with ESLint.
- `yarn test:smoke`: run the three native smoke tests on the default iOS simulator.
- `yarn test`: run all native crypto tests on the default iOS simulator; pass `--harnessRunner android` to select Android.
- `yarn example start`: start the Metro server for the example app.
- `yarn example android`: run the example app on Android.
- `yarn example ios`: run the example app on iOS.

### Sending a pull request

> **Working on your first pull request?** You can learn how from this _free_ series: [How to Contribute to an Open Source Project on GitHub](https://app.egghead.io/playlists/how-to-contribute-to-an-open-source-project-on-github).

When you're sending a pull request:

- Prefer small pull requests focused on one change.
- Verify that linters and tests are passing.
- Review the documentation to make sure it looks good.
- Follow the pull request template when opening a pull request.
- For pull requests that change the API or implementation, discuss with maintainers first by opening an issue.
