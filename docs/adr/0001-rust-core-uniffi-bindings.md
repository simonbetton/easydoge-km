# ADR 0001: Rust Core With UniFFI Bindings

## Status

Accepted

## Context

The SDK must expose feature-parity APIs for Rust backend services, Swift iOS apps, Kotlin Android apps, and Expo React Native apps.

## Decision

Implement Dogecoin key and signing logic once in Rust. Expose mobile APIs through UniFFI-generated Swift and Kotlin bindings, with native façade packages on top.

## Consequences

Cryptographic behavior has one implementation and one shared parity-vector suite. Platform packages must treat the Rust crate as their source of truth.

