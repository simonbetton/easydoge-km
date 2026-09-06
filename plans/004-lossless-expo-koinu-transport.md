# Plan 004: Make Expo monetary and integer transport lossless and crash-free

> **Executor instructions**: Follow this plan step by step. Run every
> verification command and confirm the expected result before moving to the
> next step. If anything in the "STOP conditions" section occurs, stop and
> report — do not improvise. When done, update the status row for this plan
> in `plans/README.md` — unless a reviewer dispatched you and told you they
> maintain the index.
>
> **Drift check (run first)**:
> `git diff --stat 32f1e4d..HEAD -- bindings/expo bindings/swift/Sources/EasyDogeKM bindings/swift/Tests bindings/kotlin/easydoge-km/src docs/API.md CHANGELOG.md`
> If any in-scope file changed since this plan was written, compare the
> "Current state" excerpts against the live code before proceeding; on a
> mismatch, treat it as a STOP condition. (Plan 005 also touches
> `bindings/kotlin/easydoge-km/src` and the Expo Android module — additive
> changes there are expected.)

## Status

- **Priority**: P1
- **Effort**: L
- **Risk**: HIGH (breaking change to the Expo TypeScript contract for every koinu field; native code cannot be compiled by CI today)
- **Depends on**: none
- **Category**: bug / security (fund-amount integrity)
- **Planned at**: commit `32f1e4d`, 2026-09-04
- **Audit finding**: #3 (deep audit, evidence originally collected at `04e7499`, revalidated at `32f1e4d`)
- **Executed**: 2026-09-07 by a dispatched executor; reviewed and approved. Commit `a429374` on branch `fix/expo-lossless-koinu` (worktree `.claude/worktrees/agent-a1c388586e715125a`), cut from `599ca98` and not rebased onto plan 005's branch; PR https://github.com/simonbetton/easydoge-km/pull/43. The Swift tests are wrapped in `@Suite struct WireCodecTests` so `swift test --filter WireCodecTests` selects them (reviewer-authorized adaptation). `Double` `AsyncFunction` parameters are supported by expo-modules-core (verified in the 3.0.18 sources: Kotlin `TypeConverterProvider` maps `Double::class`, Swift declares `extension Double: AnyArgument`); no on-device run was done because CI does not compile the Expo modules (finding 15).

## Why this matters

Koinu amounts are `u64` in Rust, but the Expo bridge carries them as JavaScript
`number`. Any amount above 2^53 − 1 koinu (about 90 million DOGE) loses
precision before it reaches native code, and the native converters make it
worse: Swift `UInt64(Double)` traps on negative, NaN, or too-large values and
`Int(u64)` traps above `Int.max`, so a malformed request crashes the app;
Kotlin `toLong().toULong()` silently wraps negatives into huge amounts and
`toInt().toUByte()` truncates thresholds (300 becomes 44). A fee, dust
threshold, output value, or UTXO value can therefore be altered or the process
killed by ordinary bad input. After this plan koinu values cross the bridge as
canonical decimal strings, every other integer is range-checked, and invalid
input becomes a thrown JavaScript error instead of a wrong amount or a crash.

## Wire contract (decision made by the advisor; executor implements as written)

1. **Koinu amounts are strings.** New TypeScript alias `Koinu = string`: an
   unsigned canonical decimal (`"0"` or digits with no leading zero), at most
   20 characters, numerically ≤ `18446744073709551615`. Native code accepts
   only `String` for these fields and returns them as strings.
2. **Fields that become `Koinu`** (input and output):
   `SigningEnvelopeInput.previousOutputValueKoinu`,
   `SpendableUtxo.previousOutputValueKoinu`, `TransactionOutput.valueKoinu`,
   `FeePolicy.feeRateKoinuPerKb`, `FeePolicy.dustThresholdKoinu`,
   `AuditedInput.previousOutputValueKoinu`,
   `SkippedInput.previousOutputValueKoinu`,
   `ComposeTransactionResult.inputTotalKoinu`, `.spendOutputTotalKoinu`,
   `.changeAmountKoinu`, `.feeKoinu`.
3. **Every other integer stays `number`** but must be a finite, non-negative
   safe integer within the Rust type's range; native code rejects anything
   else with a descriptive error instead of trapping or wrapping. Ranges:
   `inputIndex`, `estimatedSizeBytes`, `actualSizeBytes` → 0…2^53−1 (u64 on the
   FFI, bounded by real transaction sizes); `vout`, `lockTime`, `sequence`,
   `sighashType`, `account`, `childNumber` → u32; `version` → i32 (must be > 0,
   enforced by the core); `multisigThreshold`, `threshold`, `depth`,
   `version` (envelope) → u8; `wordCount` → u16.
4. **Defaults**: a field that is absent (`undefined`/`null`) keeps today's
   default only where the TypeScript type is optional or where the native
   code already defaults: `wordCount` → 24, `TransactionOptions.version` → 1,
   `lockTime` → 0, `sequence` → 4294967295, `sighashType` → 1,
   `SigningEnvelope.version` → 1. Every other field is required; absence is
   an error.
5. **Output u64 values that are not koinu** (`estimatedSizeBytes`,
   `actualSizeBytes`, `inputIndex`) are returned as `number` only if
   ≤ 2^53−1; otherwise native throws (cannot happen for real transactions but
   must never silently round).
6. **Errors** are thrown from the native function and surface as a rejected
   promise whose message starts with `Invalid <fieldName>:`.

Finding 6 (unknown `network`/`language`/`protection` strings fail open) is a
separate plan; do not fold it in here, but structure the new helpers so that a
strict enum parser can be added beside them later.

## Current state

- `bindings/expo/src/index.ts` — TypeScript types and `requireNativeModule` export. Koinu fields are `number` (lines 96, 127, 141, 148–149, 184, 192, 200–205). No runtime code besides the module lookup (273–276).
- `bindings/expo/ios/EasyDogeKMModule.swift` — Expo iOS module. Unsafe conversions: `UInt16(options?["wordCount"] as? Int ?? 24)` (14), `UInt32(account)` (33), `UInt8(threshold)` (80), `UInt64(inputIndex)` / `UInt32(sighashType)` (104, 107), `UInt8(intValue(...))` (334), `UInt64(intValue(...))` (356, 385), `UInt32(intValue(...))` (360, 468, 527–529), `Int32(intValue(...))` (526), `Int(u64)` on outputs (375, 540–543, 550, 562, 573), helpers `intValue` (580–588), `uint64Value` (590–604: `UInt64(int)` and `UInt64(double)` trap on negatives), `uint64Optional` (606–611), `uint8Optional` (613–615: `UInt8($0)` traps above 255).
- `bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt` — Expo Android module. Unsafe conversions: `toInt().toUInt()` (45), `account.toUInt()` (59), `threshold.toUByte()` (105), `inputIndex.toULong()` / `sighashType.toUInt()` (124, 127), `number(...).toInt().toUByte()` (285, 300, 412), `number(...).toLong().toULong()` (294, 299, 306, 408, 429, 437–438), `toLong().toUInt()` (298, 407, 451–453), `Long` outputs of u64 (322, 327, 344–351, 361–362, 371). Helpers `number` / `optionalNumber` (375–380) accept any `Number`.
- `bindings/swift/Sources/EasyDogeKM/EasyDogeKM.swift` — Swift façade package; the Expo module already does `import EasyDogeKM`. New helper file goes beside it.
- `bindings/swift/Tests/EasyDogeKMTests/EasyDogeKMTests.swift` — uses `import Testing` and `@Test func …() async throws { #expect(...) }`. Model new tests on it.
- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/EasyDogeKM.kt` — Kotlin façade; the Expo module already imports `io.easydoge.km.*`. New helper file goes beside it.
- `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/EasyDogeKMTest.kt` — uses `kotlin.test.Test`, `assertEquals`, `assertTrue`, JUnit 4 runner. Model new tests on it (a pure-Kotlin test does not need the native library override).
- `docs/API.md` line "Expo exposes the same data in camelCase JavaScript objects; signing envelope input kinds are `"p2pkh"` and `"p2sh-multisig"`." — extend it.
- `CHANGELOG.md` — `## [Unreleased]` with `### Added` / `### Changed` (and `### Security` if plans 001–003 landed).
- CI (`scripts/verify.sh`) compiles the Swift and Kotlin **façade** packages and typechecks the Expo TypeScript, but does **not** compile the Expo module files (finding 15). Their correctness is verified by review, by the shared codec tests, and by grep-based done criteria below.

Excerpt, `bindings/expo/ios/EasyDogeKMModule.swift:590-604` (today):

```swift
private func uint64Value(_ value: Any?, default fallback: UInt64) -> UInt64 {
    if let uint64 = value as? UInt64 {
        return uint64
    }
    if let int = value as? Int {
        return UInt64(int)
    }
    if let double = value as? Double {
        return UInt64(double)
    }
    if let number = value as? NSNumber {
        return number.uint64Value
    }
    return fallback
}
```

Excerpt, `bindings/expo/android/.../EasyDogeKMModule.kt:426-433` (today):

```kotlin
private fun Map<String, Any?>.toTransactionOutput(): TransactionOutput =
    TransactionOutput(
        kind = parseTransactionOutputKind(this["kind"] as? String),
        valueKoinu = number("valueKoinu", 0).toLong().toULong(),
        address = this["address"] as? String,
        opReturnDataHex = this["opReturnDataHex"] as? String,
        scriptHex = this["scriptHex"] as? String,
    )
```

Excerpt, `bindings/expo/src/index.ts:139-150` (today):

```ts
export interface TransactionOutput {
  kind: TransactionOutputKind;
  valueKoinu: number;
  address?: string | null;
  opReturnDataHex?: string | null;
  scriptHex?: string | null;
}

export interface FeePolicy {
  feeRateKoinuPerKb: number;
  dustThresholdKoinu: number;
}
```

Conventions: `.editorconfig` — 2-space indent for `.ts`, 4-space for `.swift`/`.kt`; `CONTRIBUTING.md` requires tests for new public behavior and doc updates; `scripts/check-open-source-ready.sh` fails on the uppercase "to do"/"fix me" marker words anywhere in the repo, so never write them. `CONTEXT.md` term: "Koinu — the smallest Dogecoin amount unit."

## Commands you will need

| Purpose | Command | Expected on success |
|---------|---------|---------------------|
| Expo typecheck | `npx -y -p typescript@7.0.2 tsc -p bindings/expo/tsconfig.json --noEmit` | exit 0 |
| Build native lib (needed by Swift/Kotlin tests) | `cargo build -p easydoge-km-ffi` | exit 0 |
| Swift tests | `cd bindings/swift && swift test` | all tests pass |
| Swift one test | `cd bindings/swift && swift test --filter WireCodecTests` | pass |
| Kotlin tests | `cd bindings/kotlin && ./gradlew test` | BUILD SUCCESSFUL |
| Kotlin one class | `cd bindings/kotlin && ./gradlew :easydoge-km:testDebugUnitTest --tests 'io.easydoge.km.WireCodecTest'` | BUILD SUCCESSFUL |
| Swift syntax-only check of the Expo module | `swiftc -parse bindings/expo/ios/EasyDogeKMModule.swift` | exit 0 (parses; does not type-check imports) |
| Readiness | `bash scripts/check-open-source-ready.sh` | exit 0 |
| Full suite | `./scripts/verify.sh` | exit 0 |

## Scope

**In scope** (the only files you should modify or create):

- `bindings/expo/src/index.ts`
- `bindings/expo/ios/EasyDogeKMModule.swift`
- `bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt`
- `bindings/swift/Sources/EasyDogeKM/WireCodec.swift` (create)
- `bindings/swift/Tests/EasyDogeKMTests/WireCodecTests.swift` (create)
- `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/WireCodec.kt` (create)
- `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/WireCodecTest.kt` (create)
- `docs/API.md`, `CHANGELOG.md`

**Out of scope** (do NOT touch):

- Rust crates, UniFFI records (`u64` stays `u64`), generated bindings under `bindings/swift/Sources/easydoge_km_ffi*` and `bindings/kotlin/.../uniffi/**`.
- `parseNetwork` / `parseLanguage` / `parseProtection` fail-open behavior (finding 6, separate plan).
- `bindings/expo/package.json`, podspec, Gradle files (finding 14, packaging).
- Adding CI compilation of the Expo modules (finding 15).

## Git workflow

- Branch: `fix/expo-lossless-koinu`
- Conventional Commits, e.g. `fix(expo): carry koinu amounts as decimal strings and validate integers`
- Do NOT push or open a PR unless the operator instructed it.

## Steps

### Step 1: Swift `WireCodec` in the façade package, test-first

Create `bindings/swift/Tests/EasyDogeKMTests/WireCodecTests.swift`:

```swift
import Foundation
import Testing
@testable import EasyDogeKM

@Test func koinuAcceptsCanonicalDecimalStringsOnly() throws {
    #expect(try WireCodec.koinu("0", field: "valueKoinu") == 0)
    #expect(try WireCodec.koinu("18446744073709551615", field: "valueKoinu") == UInt64.max)
    #expect(try WireCodec.koinu("9007199254740993", field: "valueKoinu") == 9_007_199_254_740_993)
    for bad in ["", "01", "-1", "1.0", "1e3", " 1", "18446744073709551616", "abc"] as [Any] {
        #expect(throws: WireCodecError.self) { try WireCodec.koinu(bad, field: "valueKoinu") }
    }
    #expect(throws: WireCodecError.self) { try WireCodec.koinu(1 as Int, field: "valueKoinu") }
    #expect(throws: WireCodecError.self) { try WireCodec.koinu(nil, field: "valueKoinu") }
    #expect(try WireCodec.optionalKoinu(nil, field: "x") == nil)
    #expect(try WireCodec.optionalKoinu("7", field: "x") == 7)
    #expect(WireCodec.koinuString(UInt64.max) == "18446744073709551615")
}

@Test func integersAreRangeCheckedAndNeverTrap() throws {
    #expect(try WireCodec.uint32(4294967295.0, field: "vout") == UInt32.max)
    #expect(try WireCodec.uint32(7 as Int, field: "vout") == 7)
    #expect(try WireCodec.uint8(255.0, field: "threshold") == 255)
    #expect(try WireCodec.uint16(24 as Int, field: "wordCount") == 24)
    #expect(try WireCodec.int32(1.0, field: "version") == 1)
    #expect(try WireCodec.uint64(9007199254740991.0, field: "inputIndex") == 9_007_199_254_740_991)
    for bad in [-1.0, 1.5, Double.nan, Double.infinity, 4294967296.0] {
        #expect(throws: WireCodecError.self) { try WireCodec.uint32(bad, field: "vout") }
    }
    #expect(throws: WireCodecError.self) { try WireCodec.uint8(256.0, field: "threshold") }
    #expect(throws: WireCodecError.self) { try WireCodec.uint32(true, field: "vout") }
    #expect(throws: WireCodecError.self) { try WireCodec.uint32("1", field: "vout") }
    #expect(throws: WireCodecError.self) { try WireCodec.uint32(nil, field: "vout") }
    #expect(throws: WireCodecError.self) { try WireCodec.uint64(9007199254740992.0, field: "inputIndex") }
    #expect(try WireCodec.safeInteger(42, field: "estimatedSizeBytes") == 42)
    #expect(throws: WireCodecError.self) { try WireCodec.safeInteger(UInt64.max, field: "estimatedSizeBytes") }
}
```

Create `bindings/swift/Sources/EasyDogeKM/WireCodec.swift`:

```swift
import Foundation

/// Raised when a JavaScript-facing value cannot be converted losslessly.
public enum WireCodecError: Error, Equatable, LocalizedError {
    case invalidKoinu(field: String)
    case invalidInteger(field: String, range: String)
    case unrepresentable(field: String)

    public var errorDescription: String? {
        switch self {
        case let .invalidKoinu(field):
            return "Invalid \(field): koinu amounts must be a canonical decimal string between 0 and 18446744073709551615"
        case let .invalidInteger(field, range):
            return "Invalid \(field): expected an integer in \(range)"
        case let .unrepresentable(field):
            return "Cannot return \(field): value exceeds JavaScript's safe integer range"
        }
    }
}

/// Lossless conversions between JavaScript-facing values and Rust integer types.
public enum WireCodec {
    public static let maxSafeInteger: UInt64 = 9_007_199_254_740_991

    public static func koinu(_ value: Any?, field: String) throws -> UInt64 {
        guard let text = value as? String, isCanonicalDecimal(text), let parsed = UInt64(text) else {
            throw WireCodecError.invalidKoinu(field: field)
        }
        return parsed
    }

    public static func optionalKoinu(_ value: Any?, field: String) throws -> UInt64? {
        if value == nil || value is NSNull { return nil }
        return try koinu(value, field: field)
    }

    public static func koinuString(_ value: UInt64) -> String {
        String(value)
    }

    public static func uint64(_ value: Any?, field: String) throws -> UInt64 {
        try integral(value, field: field, max: maxSafeInteger)
    }

    public static func uint32(_ value: Any?, field: String) throws -> UInt32 {
        UInt32(try integral(value, field: field, max: UInt64(UInt32.max)))
    }

    public static func uint16(_ value: Any?, field: String) throws -> UInt16 {
        UInt16(try integral(value, field: field, max: UInt64(UInt16.max)))
    }

    public static func uint8(_ value: Any?, field: String) throws -> UInt8 {
        UInt8(try integral(value, field: field, max: UInt64(UInt8.max)))
    }

    public static func optionalUInt8(_ value: Any?, field: String) throws -> UInt8? {
        if value == nil || value is NSNull { return nil }
        return try uint8(value, field: field)
    }

    public static func int32(_ value: Any?, field: String) throws -> Int32 {
        Int32(try integral(value, field: field, max: UInt64(Int32.max)))
    }

    public static func safeInteger(_ value: UInt64, field: String) throws -> Int {
        guard value <= maxSafeInteger else { throw WireCodecError.unrepresentable(field: field) }
        return Int(value)
    }

    private static func isCanonicalDecimal(_ text: String) -> Bool {
        guard !text.isEmpty, text.count <= 20, text.allSatisfy({ $0.isASCII && $0.isNumber }) else {
            return false
        }
        return text == "0" || !text.hasPrefix("0")
    }

    private static func integral(_ value: Any?, field: String, max: UInt64) throws -> UInt64 {
        let range = "0...\(max)"
        if value is Bool { throw WireCodecError.invalidInteger(field: field, range: range) }
        let double: Double
        switch value {
        case let int as Int:
            guard int >= 0, UInt64(int) <= max else { throw WireCodecError.invalidInteger(field: field, range: range) }
            return UInt64(int)
        case let value as Double:
            double = value
        case let number as NSNumber:
            double = number.doubleValue
        default:
            throw WireCodecError.invalidInteger(field: field, range: range)
        }
        guard double.isFinite, double >= 0, double.rounded(.towardZero) == double, double <= Double(max) else {
            throw WireCodecError.invalidInteger(field: field, range: range)
        }
        return UInt64(double)
    }
}
```

Note the `Double(max)` comparison: for `max = maxSafeInteger` the conversion is exact; for `UInt32.max` and smaller it is exact too.

**Verify**: `cargo build -p easydoge-km-ffi && cd bindings/swift && swift test --filter WireCodecTests` → both tests pass. Then `swift test` → the existing parity test still passes.

### Step 2: Kotlin `WireCodec` in the façade package, test-first

Create `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/WireCodecTest.kt`:

```kotlin
package io.easydoge.km

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class WireCodecTest {
    @Test
    fun koinuAcceptsCanonicalDecimalStringsOnly() {
        assertEquals(0uL, WireCodec.koinu("0", "valueKoinu"))
        assertEquals(ULong.MAX_VALUE, WireCodec.koinu("18446744073709551615", "valueKoinu"))
        assertEquals(9_007_199_254_740_993uL, WireCodec.koinu("9007199254740993", "valueKoinu"))
        for (bad in listOf("", "01", "-1", "1.0", "1e3", " 1", "18446744073709551616", "abc")) {
            assertFailsWith<WireCodecException> { WireCodec.koinu(bad, "valueKoinu") }
        }
        assertFailsWith<WireCodecException> { WireCodec.koinu(1, "valueKoinu") }
        assertFailsWith<WireCodecException> { WireCodec.koinu(null, "valueKoinu") }
        assertNull(WireCodec.optionalKoinu(null, "x"))
        assertEquals(7uL, WireCodec.optionalKoinu("7", "x"))
        assertEquals("18446744073709551615", WireCodec.koinuString(ULong.MAX_VALUE))
    }

    @Test
    fun integersAreRangeCheckedAndNeverWrap() {
        assertEquals(UInt.MAX_VALUE, WireCodec.uint32(4294967295.0, "vout"))
        assertEquals(7u, WireCodec.uint32(7, "vout"))
        assertEquals(255u.toUByte(), WireCodec.uint8(255.0, "threshold"))
        assertEquals(24u.toUShort(), WireCodec.uint16(24, "wordCount"))
        assertEquals(1, WireCodec.int32(1.0, "version"))
        assertEquals(9_007_199_254_740_991uL, WireCodec.uint64(9007199254740991.0, "inputIndex"))
        for (bad in listOf(-1.0, 1.5, Double.NaN, Double.POSITIVE_INFINITY, 4294967296.0)) {
            assertFailsWith<WireCodecException> { WireCodec.uint32(bad, "vout") }
        }
        assertFailsWith<WireCodecException> { WireCodec.uint8(256.0, "threshold") }
        assertFailsWith<WireCodecException> { WireCodec.uint8(300, "threshold") }
        assertFailsWith<WireCodecException> { WireCodec.uint32(true, "vout") }
        assertFailsWith<WireCodecException> { WireCodec.uint32("1", "vout") }
        assertFailsWith<WireCodecException> { WireCodec.uint32(null, "vout") }
        assertFailsWith<WireCodecException> { WireCodec.uint64(9007199254740992.0, "inputIndex") }
        assertEquals(42L, WireCodec.safeInteger(42uL, "estimatedSizeBytes"))
        assertFailsWith<WireCodecException> { WireCodec.safeInteger(ULong.MAX_VALUE, "estimatedSizeBytes") }
    }
}
```

Create `bindings/kotlin/easydoge-km/src/main/java/io/easydoge/km/WireCodec.kt`:

```kotlin
package io.easydoge.km

/** Raised when a JavaScript-facing value cannot be converted losslessly. */
class WireCodecException(message: String) : IllegalArgumentException(message)

/** Lossless conversions between JavaScript-facing values and Rust integer types. */
object WireCodec {
    const val MAX_SAFE_INTEGER: Long = 9_007_199_254_740_991L
    private val CANONICAL_DECIMAL = Regex("0|[1-9][0-9]*")

    fun koinu(value: Any?, field: String): ULong {
        val text = value as? String
        if (text == null || text.length > 20 || !CANONICAL_DECIMAL.matches(text)) {
            throw invalidKoinu(field)
        }
        return text.toULongOrNull() ?: throw invalidKoinu(field)
    }

    fun optionalKoinu(value: Any?, field: String): ULong? = if (value == null) null else koinu(value, field)

    fun koinuString(value: ULong): String = value.toString()

    fun uint64(value: Any?, field: String): ULong = integral(value, field, MAX_SAFE_INTEGER).toULong()

    fun uint32(value: Any?, field: String): UInt = integral(value, field, UInt.MAX_VALUE.toLong()).toUInt()

    fun uint16(value: Any?, field: String): UShort = integral(value, field, UShort.MAX_VALUE.toLong()).toUShort()

    fun uint8(value: Any?, field: String): UByte = integral(value, field, UByte.MAX_VALUE.toLong()).toUByte()

    fun optionalUInt8(value: Any?, field: String): UByte? = if (value == null) null else uint8(value, field)

    fun int32(value: Any?, field: String): Int = integral(value, field, Int.MAX_VALUE.toLong()).toInt()

    fun safeInteger(value: ULong, field: String): Long {
        if (value > MAX_SAFE_INTEGER.toULong()) {
            throw WireCodecException("Cannot return $field: value exceeds JavaScript's safe integer range")
        }
        return value.toLong()
    }

    private fun invalidKoinu(field: String) =
        WireCodecException("Invalid $field: koinu amounts must be a canonical decimal string between 0 and 18446744073709551615")

    private fun integral(value: Any?, field: String, max: Long): Long {
        val range = "0...$max"
        val invalid = { WireCodecException("Invalid $field: expected an integer in $range") }
        return when (value) {
            is Boolean -> throw invalid()
            is Int, is Long, is Short, is Byte -> {
                val long = (value as Number).toLong()
                if (long < 0 || long > max) throw invalid()
                long
            }
            is Number -> {
                val double = value.toDouble()
                if (!double.isFinite() || double < 0 || double != Math.floor(double) || double > max.toDouble()) {
                    throw invalid()
                }
                double.toLong()
            }
            else -> throw invalid()
        }
    }
}
```

**Verify**: `cd bindings/kotlin && ./gradlew :easydoge-km:testDebugUnitTest --tests 'io.easydoge.km.WireCodecTest'` → BUILD SUCCESSFUL. Then `./gradlew test` → the existing parity test still passes (requires `cargo build -p easydoge-km-ffi` beforehand).

### Step 3: TypeScript contract

In `bindings/expo/src/index.ts`:

1. Add near the top (after the `Language` type):

```ts
/**
 * Koinu amount as a canonical unsigned decimal string: "0" or digits with no
 * leading zero, at most 18446744073709551615. JavaScript numbers cannot
 * represent every u64 koinu value, so amounts cross the native bridge as
 * strings. Use koinuFromBigInt / koinuToBigInt for arithmetic.
 */
export type Koinu = string;

export const MAX_KOINU = 18446744073709551615n;

const CANONICAL_DECIMAL = /^(0|[1-9][0-9]*)$/;

export function isKoinu(value: unknown): value is Koinu {
  return (
    typeof value === "string" &&
    value.length <= 20 &&
    CANONICAL_DECIMAL.test(value) &&
    BigInt(value) <= MAX_KOINU
  );
}

export function koinuFromBigInt(value: bigint): Koinu {
  if (value < 0n || value > MAX_KOINU) {
    throw new RangeError(`koinu amount out of range: ${value}`);
  }
  return value.toString(10);
}

export function koinuToBigInt(value: Koinu): bigint {
  if (!isKoinu(value)) {
    throw new RangeError(`invalid koinu amount: ${String(value)}`);
  }
  return BigInt(value);
}
```

2. Change the field types listed in the wire contract from `number` to `Koinu` (optional ones become `Koinu | null` where they were `number | null`). Leave all other numeric fields as `number`.

**Verify**: `npx -y -p typescript@7.0.2 tsc -p bindings/expo/tsconfig.json --noEmit` → exit 0. `grep -c "Koinu;" bindings/expo/src/index.ts` → 11 lines end in `: Koinu;` or `: Koinu | null;` (count both forms: `grep -cE ": Koinu( \| null)?;" bindings/expo/src/index.ts` → 11).

### Step 4: Rewrite the Expo iOS converters

In `bindings/expo/ios/EasyDogeKMModule.swift`:

1. Change typed numeric closure parameters to `Double` so Expo never truncates before validation: `account: Int` → `account: Double` (line 27), `threshold: Int` → `Double` (77), `inputIndex: Int, … sighashType: Int` → `Double` (100). Convert with `WireCodec.uint32(account, field: "account")`, `WireCodec.uint8(threshold, field: "threshold")`, `WireCodec.uint64(inputIndex, field: "inputIndex")`, `WireCodec.uint32(sighashType, field: "sighashType")`. `generateMnemonic` `wordCount`: `WireCodec.uint16(options?["wordCount"] ?? 24, field: "wordCount")`.
2. Delete the private helpers `intValue`, `uint64Value`, `uint64Optional`, `uint8Optional` and replace every call site:
   - koinu fields → `try WireCodec.koinu(value["…"], field: "…")` / `optionalKoinu`.
   - `inputIndex` → `try WireCodec.uint64(value["inputIndex"], field: "inputIndex")`.
   - `version` (envelope) → `try WireCodec.uint8(value["version"] ?? 1, field: "version")`; `sighashType` → `uint32(value["sighashType"] ?? 1, …)`; `vout` → `uint32`; `multisigThreshold` → `optionalUInt8`; `TransactionOptions.version` → `int32(value["version"] ?? 1, …)`; `lockTime` → `uint32(value["lockTime"] ?? 0, …)`; `sequence` → `uint32(value["sequence"] ?? 4294967295.0, …)`.
   - Mark the affected `fromDictionary` functions `throws` and propagate with `try` (`FeePolicy.fromDictionary`, `TransactionOptions.fromDictionary`, `SigningEnvelopeSignature.fromDictionary`, and callers).
3. Outputs: replace `Int(previousOutputValueKoinu)`, `Int(inputTotalKoinu)`, `Int(spendOutputTotalKoinu)`, `Int(changeAmountKoinu)`, `Int(feeKoinu)` with `WireCodec.koinuString(...)`; replace `Int(estimatedSizeBytes)`, `Int(inputIndex)` and `actualSizeBytes.map { Int($0) }` with `try WireCodec.safeInteger(..., field: "…")` (make those `asDictionary()` functions `throws` and add `try` at call sites).

**Verify**: `swiftc -parse bindings/expo/ios/EasyDogeKMModule.swift` → exit 0. `grep -nE "UInt(8|16|32|64)\((intValue|uint64Value|inputIndex|account|threshold|sighashType)|Int\((previousOutputValueKoinu|inputTotalKoinu|spendOutputTotalKoinu|changeAmountKoinu|feeKoinu|inputIndex|estimatedSizeBytes)\)|func (intValue|uint64Value|uint64Optional|uint8Optional)" bindings/expo/ios/EasyDogeKMModule.swift` → no matches. `grep -c "WireCodec\." bindings/expo/ios/EasyDogeKMModule.swift` → ≥ 30.

### Step 5: Rewrite the Expo Android converters

In `bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt`:

1. Add `import io.easydoge.km.WireCodec`.
2. Change typed numeric lambda parameters `account: Int`, `threshold: Int`, `inputIndex: Int`, `sighashType: Int` to `Double` and convert via `WireCodec.uint32(account, "account")`, `WireCodec.uint8(threshold, "threshold")`, `WireCodec.uint64(inputIndex, "inputIndex")`, `WireCodec.uint32(sighashType, "sighashType")`. `wordCount`: `WireCodec.uint16(options?.get("wordCount") ?: 24, "wordCount")`.
3. Delete `number` / `optionalNumber` and replace every call site with the matching `WireCodec` function, using the same defaults as the iOS step (`this["version"] ?: 1`, `this["lockTime"] ?: 0`, `this["sequence"] ?: 4294967295.0`, `this["sighashType"] ?: 1`).
4. Outputs: koinu fields → `WireCodec.koinuString(...)`; `inputIndex`, `estimatedSizeBytes`, `actualSizeBytes` → `WireCodec.safeInteger(..., "…")`.

**Verify**: `grep -nE "\.toULong\(\)|\.toUByte\(\)|\.toUInt\(\)|\.toUShort\(\)|fun Map<String, Any\?>\.(number|optionalNumber)" bindings/expo/android/src/main/java/io/easydoge/km/expo/EasyDogeKMModule.kt` → no matches. `grep -c "WireCodec\." …EasyDogeKMModule.kt` → ≥ 30. Gradle does not compile this module in CI; if a Kotlin compiler is available locally, `kotlinc` will not resolve Expo symbols either — rely on the grep checks plus a careful read-through against Step 4's Swift version for symmetry.

### Step 6: Documentation

- `docs/API.md`: replace the sentence starting "Expo exposes the same data in camelCase JavaScript objects" with: "Expo exposes the same data in camelCase JavaScript objects. Koinu amounts (`valueKoinu`, `previousOutputValueKoinu`, `feeRateKoinuPerKb`, `dustThresholdKoinu`, and the compose result totals) are canonical decimal strings because JavaScript numbers cannot represent every `u64`; use `koinuFromBigInt` / `koinuToBigInt` from the package for arithmetic. All other integers are JavaScript numbers that must be non-negative safe integers within the native range; out-of-range or non-integer values reject the promise with `Invalid <field>: …`. Signing envelope input kinds are `\"p2pkh\"` and `\"p2sh-multisig\"`."
- `CHANGELOG.md` `### Changed`: "**Breaking (Expo)**: koinu amounts in the Expo API are now decimal strings (`Koinu`) instead of numbers, and every other integer field is validated on the native side. Previously values above 2^53 lost precision, negative or fractional values could wrap on Android or crash on iOS."

**Verify**: `bash scripts/check-open-source-ready.sh` → exit 0.

### Step 7: Full verification

**Verify**: `./scripts/verify.sh` → exit 0 (runs Swift and Kotlin tests including `WireCodecTests` / `WireCodecTest`, and the Expo typecheck).

## Test plan

- Swift: `WireCodecTests` (`koinuAcceptsCanonicalDecimalStringsOnly`, `integersAreRangeCheckedAndNeverTrap`) in `bindings/swift/Tests/EasyDogeKMTests/WireCodecTests.swift`, modeled on the existing `@Test` in `EasyDogeKMTests.swift`.
- Kotlin: `WireCodecTest` (`koinuAcceptsCanonicalDecimalStringsOnly`, `integersAreRangeCheckedAndNeverWrap`) in `bindings/kotlin/easydoge-km/src/test/java/io/easydoge/km/WireCodecTest.kt`, modeled on `EasyDogeKMTest.kt`.
- TypeScript: typecheck only (the package has no test runner). The exported helpers are pure and small.
- Expo native modules: not compilable in CI (finding 15). Manual check if an Expo dev client is available: call `composeAndSignTransaction` with `valueKoinu: "18446744073709551615"` and expect a core error about insufficient funds (not a crash or a silently different amount); call with `valueKoinu: -1` and expect `Invalid valueKoinu: …`.

## Done criteria

Machine-checkable. ALL must hold:

- [ ] `npx -y -p typescript@7.0.2 tsc -p bindings/expo/tsconfig.json --noEmit` exits 0
- [ ] `grep -cE ": Koinu( \| null)?;" bindings/expo/src/index.ts` → `11`
- [ ] `grep -n "export function koinuFromBigInt\|export function koinuToBigInt\|export function isKoinu" bindings/expo/src/index.ts` → 3 matches
- [ ] `(cd bindings/swift && swift test)` exits 0 and reports `WireCodecTests` passing
- [ ] `(cd bindings/kotlin && ./gradlew test)` exits 0 and `bindings/kotlin/easydoge-km/build/test-results/testDebugUnitTest/` (or `testReleaseUnitTest/`) contains a `WireCodecTest` result with 0 failures
- [ ] The Step 4 and Step 5 grep checks return no unsafe conversions in either Expo module
- [ ] `swiftc -parse bindings/expo/ios/EasyDogeKMModule.swift` exits 0
- [ ] `grep -n "decimal string" docs/API.md CHANGELOG.md` → ≥ 1 match in each
- [ ] `./scripts/verify.sh` exits 0
- [ ] `git status --porcelain` lists only in-scope files
- [ ] `plans/README.md` status row updated

## STOP conditions

Stop and report back (do not improvise) if:

- The "Current state" excerpts do not match the live code.
- `swift test` or `./gradlew test` cannot run on the executor machine (missing Swift 6 / JDK 17 / Android SDK) — report which, do not skip the tests.
- Expo Modules API rejects `Double` as an `AsyncFunction` parameter type on either platform (check the installed `expo-modules-core` if a host app is available; otherwise keep `Double` and flag it in the report).
- Making the TypeScript change requires touching `bindings/expo/package.json` or the build config.
- You find another numeric field not listed in the wire contract — add it to the report rather than choosing a type for it.

## Maintenance notes

- `WireCodec` (Swift and Kotlin) is now the only place JavaScript values become Rust integers; new Expo functions must route every number through it and every u64 koinu output through `koinuString`.
- Finding 6 (fail-open enum parsing) should add strict `parseNetwork` / `parseLanguage` / `parseProtection` equivalents next to `WireCodec` in the same façade packages, with the same test style.
- Finding 15 (compile the Expo modules in CI) is the real safety net for Steps 4–5; until it lands, any change to the Expo modules needs a manual dev-client build before release.
- Reviewer focus: symmetry between the Swift and Kotlin modules (same defaults, same field names in error messages) and that no `Int(...)` / `.toLong()` conversion of a koinu field survived.
