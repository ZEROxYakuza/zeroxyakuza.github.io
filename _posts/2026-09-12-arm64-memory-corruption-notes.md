---
title: "ARM64 Memory Corruption Notes"
date: 2026-09-12 14:00:00 +0200
categories: [Userland, Reverse Engineering, Exploitation]
tags: [arm64, assembly, exploitation, reversing]
description: "Notes on registers, calling conventions and memory corruption primitives while learning ARM64 exploitation."
---

## Registers

The general-purpose registers are `X0` through `X30`, with the lower 32-bit views exposed as `W0` through `W30`.

The link register is `X30` (`LR`).

## Calling convention

For AArch64, the first arguments are normally passed in `X0`–`X7`, while `X0` is also commonly used for return values.

A useful mental model is:

```text
X0-X7    arguments / return value
X8       indirect result location / temporary
X29      frame pointer
X30      link register
SP       stack pointer
PC       program counter
```

## Research habit

When reversing a function, annotate:

1. Prologue / epilogue
2. Stack frame size
3. Register preservation
4. Indirect calls
5. Bounds checks
6. Pointer arithmetic

The goal is to build a precise model before attempting to reason about exploitability.
