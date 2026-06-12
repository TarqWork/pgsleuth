// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! Core types for pgsleuth.
//!
//! This crate defines the shared vocabulary used by collectors, the rule
//! engine, and the `OTel` emitter. The most important type is [`Finding`] —
//! the structured output of any diagnostic check. The Python brain consumes
//! findings as JSON; it never sees the database directly.
//!
//! The [`Finding`] envelope here is a *placeholder skeleton* that matches
//! [design doc 001](../../../docs/design/001-rule-schema.md). Fields and
//! invariants are pinned; the rule engine, manifest loader, and evaluators
//! land in follow-up issues. Bumping [`FINDING_SCHEMA_VERSION`] is the
//! contract change the brain watches for.

mod finding;
mod window;

pub use finding::{
    AttributeValue, Finding, PgInstanceRef, PgRole, Remediation, Severity, Tier,
    FINDING_SCHEMA_VERSION,
};
pub use window::{BreachState, ConsecutiveBreachCounter};
