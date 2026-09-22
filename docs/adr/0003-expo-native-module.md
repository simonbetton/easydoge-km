# ADR 0003: Expo Native Module

## Status

Accepted

## Context

The React Native API must call the Rust implementation for derivation and signing, and native platform adapters for storage.

## Decision

Ship the React Native package as an Expo Modules API native module for EAS/custom dev-client builds.

## Consequences

The package does not support Expo Go. Its native Swift/Kotlin modules call the Rust-backed wrappers and platform storage adapters. Consuming builds must supply the native library/module dependencies described in [the bindings guide](../../bindings/README.md#integration-status). Workspace CI typechecks the TypeScript surface but does not compile or run the Expo native modules. Storage inherits the limitations in [the security model](../SECURITY_MODEL.md#storage-boundaries).
