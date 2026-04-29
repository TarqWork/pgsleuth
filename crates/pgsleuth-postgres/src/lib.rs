// Copyright 2026 pgsleuth contributors
// SPDX-License-Identifier: Apache-2.0

//! Postgres collectors.
//!
//! Each collector queries a specific set of `pg_stat_*` views and produces
//! raw observations. Rules consume observations and produce findings.
//!
//! Pre-alpha: empty scaffold. First collector lands week 3.

#![allow(missing_docs)] // pre-alpha

pub mod stat_statements {
    //! `pg_stat_statements` collector. Phase 1, week 3.
}

pub mod stat_activity {
    //! `pg_stat_activity` collector for live-session diagnostics. Phase 1, week 4.
}
