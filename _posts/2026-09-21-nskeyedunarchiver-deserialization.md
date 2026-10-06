---
title: "NSKeyedUnarchiver & Deserialization Attacks"
date: 2026-09-21 09:00:00 +0200
categories: [Userland, Reverse Engineering, Vulnerability Research]
tags: [macos, ios, objective-c, deserialization, reverse-engineering]
description: "Understanding keyed archiving, object graphs and the security boundary around NSKeyedUnarchiver."
---

{% include code-note.html %}

## Introduction

`NSKeyedUnarchiver` is Apple's Foundation mechanism for reconstructing object graphs from keyed archive data.

It appears in areas such as state restoration, serialization, caches and IPC-related workflows.

The important security question is not simply *"can an attacker control the archive?"* but:

> What objects can be instantiated, what classes participate in decoding, and what code executes during reconstruction?

## The basic pipeline

At a high level:

```text
bplist / archive
      |
      v
NSKeyedUnarchiver
      |
      v
object graph reconstruction
      |
      +---- initWithCoder:
      |
      +---- decodeObjectForKey:
      |
      v
application objects
```

## Security boundary

A useful research workflow is to identify:

1. The archive entry point.
2. Whether the input is attacker-controlled.
3. The permitted classes.
4. Custom `initWithCoder:` implementations.
5. Objects reachable through decoded properties.
6. Side effects triggered during reconstruction.

## Next steps

For a real research target, trace the decoding path in LLDB, inspect the class hierarchy in Hopper/IDA/Ghidra, and build a minimal controlled archive in a lab environment.
