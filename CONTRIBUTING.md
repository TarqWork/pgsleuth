# Contributing to pgsleuth

Thank you for your interest. pgsleuth is in **pre-alpha**. We're building in public — the repo is open so the work is visible — but we're not ready to accept code contributions yet.

## What we welcome right now

- **Design feedback.** Read [`docs/design/000-architecture.md`](docs/design/000-architecture.md) and open an issue with questions, pushback, or alternatives we should consider.
- **Use-case input.** If you operate Postgres in production and have observability pain, open an issue describing the workflow you wish existed.
- **Spelling, grammar, broken-link fixes.** Small docs PRs are welcome.

## What we're deferring until v0.2

- Code contributions (rules, collectors, brain agents).
- Feature requests beyond the v1.0 roadmap.
- Tests, benchmarks, and tooling improvements.

There's a reason: solo development needs a stable architecture before contributions help. Reviewing PRs against a shifting design wastes everyone's time. Once v0.2 ships and the core architecture is committed, we'll open contributions properly.

## Hard scope rules (non-negotiable until v1.0)

- **Postgres only.** No MySQL, MongoDB, or other databases.
- **No proprietary UI.** OTel-native output only.
- **No SaaS / hosted offering during the OSS build phase.** A hosted commercial tier is planned post-v0.2 — it will not gate OSS features.
- **No public advertising before v0.2.** Repo is public; no HN, Twitter, or blog launch until the LLM plan-explainer demo is shippable.

## Code of conduct

Standard: be kind, assume good faith, don't be a jerk. We'll adopt a formal CoC (likely Contributor Covenant) before opening contributions.

## License

By submitting any contribution (issue text, docs PR, design feedback), you agree it may be incorporated into pgsleuth under the [Apache 2.0 license](LICENSE).

A formal CLA may be introduced before v0.2 to keep relicensing options open. If/when it lands, existing contributors will be asked to sign retroactively.
