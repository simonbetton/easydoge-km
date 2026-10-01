# @easydoge/km-expo

Expo Modules API bridge for the EasyDoge Dogecoin key-management SDK. The native modules call the Rust core through UniFFI, so derivation and signing run offline on the device.

The API, wire formats, and known limitations are documented in the [API guide](https://github.com/simonbetton/easydoge-km/blob/main/docs/API.md) and the [security model](https://github.com/simonbetton/easydoge-km/blob/main/docs/SECURITY_MODEL.md). Read the storage boundaries in the security model before relying on stored-wallet handles.

## Requirements

- Expo SDK 53 or newer in a development build or EAS build. Expo Go cannot load this module. The repository's host-app build check uses Expo SDK 57; older SDKs in the range are not built by it.
- iOS deployment target 16.4 or newer. Expo SDK 53, 54, and 55 default to 15.1, and autolinking skips pods whose deployment target is higher than the app's; raise it with `expo-build-properties` (`ios.deploymentTarget: "16.4"`).
- Android `minSdkVersion` 24 or newer.

## Install

The package is not published to a registry yet. Build a tarball from the [easydoge-km](https://github.com/simonbetton/easydoge-km) workspace and install it:

```sh
./scripts/build-apple-xcframework.sh
./scripts/build-android-native-libs.sh
./scripts/pack-expo-package.sh          # prints dist/expo/easydoge-km-expo-<version>.tgz
npm install /path/to/easydoge-km-expo-<version>.tgz
npx expo prebuild
```

## Usage

```ts
import EasyDogeKM from "@easydoge/km-expo";

const mnemonic = await EasyDogeKM.generateMnemonic({ wordCount: 24 });
const valid = await EasyDogeKM.validateMnemonic(mnemonic.phrase, "english");
```

Koinu amounts cross the bridge as decimal strings; use `koinuFromBigInt` and `koinuToBigInt` for arithmetic.

## What the tarball contains

- `build/`: compiled JavaScript and TypeScript declarations.
- `ios/`: the Expo module source and three CocoaPods specs. `EasyDogeKMFFI` (Swift module `easydoge_km_ffi`) holds the generated UniFFI Swift and the prebuilt XCFramework, `EasyDogeKM` holds the Swift wrapper and Keychain adapter, and `EasyDogeKMExpo` holds the Expo module.
- `android/`: one Gradle library project with the Expo module source, the Kotlin wrapper, the generated UniFFI Kotlin, and `jniLibs` for `armeabi-v7a`, `arm64-v8a`, `x86`, and `x86_64`. It links JNA and `androidx.biometric`, so the app must keep AndroidX enabled (the Expo default).
- `vendor-manifest.json`: the source commit and a SHA-256 digest for every vendored file.

The native libraries are prebuilt from the Rust workspace. Bit-for-bit reproducibility of those binaries is not verified.
