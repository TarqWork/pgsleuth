//! Companion binary required by pgrx's SQL-generation step.
//!
//! `cargo pgrx package` / `cargo pgrx schema` builds this binary,
//! runs it, and lets pgrx's `pgrx_embed!` macro introspect the
//! crate's `#[pg_extern]` items to emit `pgsleuth--<version>.sql`.
//!
//! The bin target's name must be exactly `pgrx_embed_<crate-name>`
//! — pgrx hardcodes that lookup. See the matching `[[bin]]` entry
//! in `Cargo.toml`.

::pgrx::pgrx_embed!();
