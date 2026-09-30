# ADR 0003: Expo Native Module

## Status

Accepted

## Context

The React Native API must call the Rust implementation for derivation and signing, and native platform adapters for storage.

## Decision

Ship the React Native package as an Expo Modules API native module for EAS/custom dev-client builds.

## Consequences

The package does not support Expo Go. Its native Swift/Kotlin modules call the Rust-backed wrappers and platform storage adapters. The npm package vendors those wrappers, the generated UniFFI sources, and prebuilt native libraries at pack time, so consuming builds need no workspace paths; see [the bindings guide](../../bindings/README.md#integration-status). Workspace CI typechecks the TypeScript surface, and a separate `Expo Native` workflow compiles and links the native modules inside a minimal host app; no automated check runs them. Storage inherits the limitations in [the security model](../SECURITY_MODEL.md#storage-boundaries).
