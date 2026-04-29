# Managed Postgres data access audit

**Status:** TODO — week 1 spike, ~1 day.

## Question being answered

For RDS / Aurora / Cloud SQL, what observability data is actually accessible from outside the host, and how rich, fresh, and expensive is it?

## Approach

Stand up a free-tier or trial instance of each, connect, audit:

### Per platform

For each of: RDS PG17, Aurora PG (latest), Cloud SQL PG17

- [ ] `pg_stat_statements` — confirm enable steps (parameter group changes, reboot)
- [ ] `auto_explain` to log destination — confirm it works
- [ ] How are logs accessible? (CloudWatch Logs / Cloud Logging / direct download)
- [ ] Latency from log emit to log readable via API?
- [ ] Cost per GB ingested + retrieved
- [ ] Format of the log entries — is auto_explain output cleanly parseable, or do we have to deal with line wrapping / log prefix muddling?
- [ ] Performance Insights / Query Insights API — what does it actually return? Sample request + response.
- [ ] Enhanced Monitoring (RDS) — what OS-level metrics? Frequency? Cost?
- [ ] Is `pg_stat_io` (PG16+) usable?

## Verdict per platform

| Platform | Tier 1 viable | Tier 2 viable | Notes |
|---|---|---|---|
| RDS PostgreSQL | TBD | TBD | |
| Aurora PostgreSQL | TBD | TBD | |
| Cloud SQL | TBD | TBD | |

## What this changes in the architecture

TBD — fill in based on findings. Likely candidates:
- Tier 2 collector design (one collector per cloud vs unified abstraction).
- Whether we need to support Performance Insights as a primary data source (might be richer than CloudWatch logs of `auto_explain`).
- Whether v0.2 launch should demo on managed at all, or stay self-managed-only until v1.0.

## Notes / scratch
