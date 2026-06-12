// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry emitter for pgsleuth.
//!
//! Findings are emitted as OTLP. We follow the `OTel` database semantic
//! conventions where applicable, with a `pgsleuth.*` namespace for
//! pgsleuth-specific attributes (`rule_id`, `tier`, `severity`).
//!
//! Pre-alpha: scaffold only. First emit lands week 4.

#![allow(missing_docs)] // pre-alpha
