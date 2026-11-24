# Session Management in Go with Redis and Lua

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Redis](https://img.shields.io/badge/Redis-6+-DC382D?style=flat&logo=redis)](https://redis.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Production-grade refresh token implementation for Go services, using Redis and Lua scripts to enforce a single, atomic invariant: **a session has exactly one live refresh token at any moment.**

Companion code for the Medium series: [Managing Sessions in Go with Redis and Lua](https://medium.com/@dositadi/managing-sessions-in-go-with-redis-and-lua-44684e7e6188).

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Testing](#testing)
- [Key Design Decisions](#key-design-decisions)
- [The Series](#the-series)
- [License](#license)

## Overview

Most session bugs aren't in the login handler. They're in the quiet parts: the token that lives for 30 days, the logout button that doesn't really log anyone out, the stolen token that keeps working because nothing on the server remembers it exists.

This project solves those problems by trading the convenience of self-contained JWTs for server-side state, which unlocks three things JWTs alone cannot give you:

1. **Instant revocation** — kill a session in one `DEL`
2. **Theft detection** — distinguish a lost HTTP response from a stolen token
3. **Atomic rotation** — no race conditions between concurrent refresh requests

## Features

- **Opaque tokens, hashed at rest** — the raw token goes to the client and never touches Redis; Redis stores SHA-256 hashes
- **Lua for atomicity** — every mutation runs as a single Redis script with no `WATCH`, no retry loops, no `CROSSSLOT` surprises on Cluster
- **Hash tags for Cluster** — `{<session id>}` in every key name keeps a session's keys on the same shard
- **Grace window for replays** — a short leeway (default 10s) after rotation lets a lost response be retried without triggering theft detection
- **Fail closed** — Redis outages surface as `ErrTransient`, never as "session not found"
- **Zero mutable state** — the `Manager` is built once at startup and shared across all requests

## Architecture
