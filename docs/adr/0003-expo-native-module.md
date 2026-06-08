# ADR 0003: Expo Native Module

## Status

Accepted

## Context

The React Native API must call the native Rust implementation, including secure storage and signing behavior.

## Decision

Ship the React Native package as an Expo Modules API native module for EAS/custom dev-client builds.

## Consequences

The package does not support Expo Go. Apps get native Swift/Kotlin execution and can use platform secure-storage adapters.

