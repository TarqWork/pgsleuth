
# Multi-Signal Threat Detection for DBAs
Standard monitoring tools often fail because they track "lagging indicators" (like high CPU) rather than the "leading signals" that cause the high CPU. For a Database Administrator (DBA), the highest value telemetry comes from correlating physical kernel events with internal database states. This report evaluates the 10 most difficult performance issues to track and defines the multi-signal logic required to trigger proactive "threat alarms."

## Architectural Scope: Universal vs. PostgreSQL-Specific

Not all database threats are equal. While resource-based issues (I/O, CPU, Memory) are universal, architectural choices like PostgreSQL’s **Process-per-Connection** model and **Tuple-based MVCC** create unique failure modes that do not exist in multi-threaded or undo-log-based engines like MySQL or Oracle.

|**Issue**|**Criticality**|**DB Scope**|**Technical Reason**|
|---|---|---|---|
|**TXID Wraparound**|Extreme|**PostgreSQL Only**|32-bit ID limits and inline row freezing are not required in undo-log-based DBs (Oracle/MySQL).|
|**Vacuum Death Spiral**|High|**PostgreSQL Only**|PostgreSQL stores dead tuples inline in the main table; others use separate rollback segments.|
|**Connection Storms**|High|**PG-Critical**|PG’s process-per-connection model is significantly more expensive than MySQL’s multi-threading.|
|**Fsync Jitter**|High|Universal|Every ACID DB must wait for the WAL/Redo log to hit stable storage before committing.|
|**Plan Regressions**|Moderate|Universal|All cost-based optimizers can flip plans when statistics or data distributions shift.|
|**THP Compaction**|Moderate|Universal|Linux kernel memory management features like THP impact all large-memory applications.|

## Top 10 Multi-Signal DBA Alarms

The following alarms are designed to be "threat-based," meaning they only fire when multiple orthogonal signals intersect to confirm a specific bottleneck.

### 1. Alarm: Silent Query Plan Regression

- **The Problem:** The query planner silently switches from an efficient index scan to a slow sequential scan due to stale statistics.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (DB):** SQL Query Hash (via USDT/pg_stat_statements) has a stable execution count but rising `total_time`.
        
    - **Signal B (Kernel):** Sudden spike in `vfs_read` or `block_rq_issue` events specifically for that PID.
        
    - **Alarm Trigger:** Fire if (I/O per Query) increases by $>5\times$ without a change in (Rows Returned).

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for block I/O accounting, plus `BPF_PROG_TYPE_UPROBE` (or USDT) on Postgres to tag events with a query hash.
    - **Attach points:** tracepoints `block:block_rq_issue` and `block:block_rq_complete` (per-PID byte counts and latency); kprobes on `vfs_read` / `vfs_write` if finer-grained syscall attribution is needed; uprobe on `exec_simple_query` / `PortalRun` (or USDT `postgresql:query__start` / `query__done`) to bind the I/O burst to a SQL hash.
    - **Primary data:** bytes read, request latency, and request count per `(pid, query_hash)` tuple — the ratio that drives the "I/O per Query" trigger.
	**Question** : is there a better way? Why not have a collection of all query hashes of most frequent queries with their plan -that could all be done in DB??  if it changes - why do this block issue kernal probe every time - when directly measure plan every day/hour via extension could explain ?? 

	**Answer:**
	- **DBA:** Yes — `pg_store_plans` or `auto_explain` already capture plan-per-query over time; diffing plans + `pg_stat_statements.total_time` tells you when a plan flipped. That's the right primary detector.
	- **SysAdmin:** Running `block_rq_*` continuously to catch plan flips is expensive and noisy — the kernel sees thousands of unrelated I/Os to filter through.
	- **Linux dev:** The kernel probes give the *symptom* (more I/O per query); the plan store gives the *cause* (different plan chosen). Cause-side detection is cheaper and unambiguous.
	- **Architect:** Demote eBPF here to a *confirmer*, not a detector. Detector = extension polling `pg_store_plans` + `pg_stat_statements` hourly. eBPF kicks in *on-demand* only when the extension flags a candidate, to prove the I/O actually moved.
	- **Verdict:** Primary = DB extension. eBPF = optional confirmation pass, not always-on.
	

### 2. Alarm: Micro-Contention (LWLock/Spinlock)

- **The Problem:** Processes spend massive CPU cycles "spinning" or waiting for short-lived internal locks that standard polling cannot see.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (Kernel):** High CPU usage on a PID that is NOT in the `Running` state (visible via `sched_switch`).
        
    - **Signal B (DB):** Wait events in `pg_stat_activity` showing `LWLock` or `Spinlock` types.
        
    - **Alarm Trigger:** Fire if "off-CPU time" spent in a spin-wait exceeds 10% of total process time.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for scheduler events; `BPF_PROG_TYPE_UPROBE` (or USDT) on Postgres lock primitives.
    - **Attach points:** tracepoints `sched:sched_switch` and `sched:sched_wakeup` to compute off-CPU intervals; kprobe on `finish_task_switch` as a fallback when tracepoints are unavailable; uprobe on `LWLockAcquire` / `LWLockRelease` (or USDT `postgresql:lwlock__wait__start` / `lwlock__wait__done`) to label the wait with a lock tranche.
    - **Primary data:** off-CPU duration per `(pid, lock_tranche)` and stack trace at the blocking point — distinguishes spin-wait from genuine I/O wait.

### 3. Alarm: Storage Layer "Choke" (Fsync Jitter)

- **The Problem:** Cloud storage stalls (P99 latency spikes) causing a backlog of database commits.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (Kernel):** High latency in `block_rq_complete` for the device containing the WAL/Redo logs.
        
    - **Signal B (DB):** Backend states stuck in "Wait for WAL" or high `wal_buffers_full` counters.
        
    - **Alarm Trigger:** Fire if commit latency exceeds 10ms for more than 3 consecutive intervals.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for block-layer latency; `BPF_PROG_TYPE_KPROBE` / `kretprobe` for fsync-specific timing.
    - **Attach points:** tracepoints `block:block_rq_issue` and `block:block_rq_complete` (record `dev` + `sector` to filter for the WAL device); kprobe + kretprobe pair on `vfs_fsync_range` (and/or `do_fsync`) to measure per-call fsync latency; optional uprobe on Postgres `XLogFlush` to attribute fsync time to a backend.
    - **Primary data:** histogram of fsync and block-completion latency keyed by device — surfaces P99 tail without polling.
- Question : - Assume typically postgress is the only major or real program on a machine - then what's the OS level view that can easily give this? Do we need to kernel hook for latency in block I/O? 

- **Answer:**
    - **DBA:** Postgres 14+ exposes `pg_stat_wal.wal_sync_time` and (with `track_io_timing=on`) `pg_stat_database.blk_write_time` — per-DB fsync and write latency, directly from the catalog.
    - **SysAdmin:** `iostat -x 1` gives per-device `w_await` / `r_await` / `aqu-sz`; `/proc/diskstats` has cumulative counters. On a dedicated PG host, per-device == per-PG. For one-off diagnosis, this is plenty.
    - **Linux dev:** `/proc/diskstats` only gives means and cumulative totals — you can't derive P99 without high-rate sampling. Block tracepoints give true *distributions* and per-request latency cheaply.
    - **Architect:** On a single-tenant PG host, `iostat` + `pg_stat_wal` polling at 1Hz solves the *alarm*. eBPF earns its place when you need (a) tail-latency resolution (P99.9), (b) shared-host PID attribution, or (c) per-fsync correlation with backend commit. For a v0 skeleton it's still the right vehicle because the pipeline scales to those harder cases.
    - **Verdict:** Polling is sufficient for the *alarm*; eBPF buys headroom for harder environments and tail-latency fidelity.

### 4. Alarm: Buffer Cache Thrashing

- **The Problem:** The database is constantly reading from disk because the hot dataset no longer fits in `shared_buffers`.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (DB):** `pg_statio_user_tables` shows falling Cache Hit Ratio.
        
    - **Signal B (Kernel):** High frequency of `mm_vmscan_write_folio` (evictions) for memory pages mapped to the database.
        
    - **Alarm Trigger:** Fire if (Physical Reads) > (Logical Reads) for tables that historically had 99% hit rates.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for VM reclaim events; `BPF_PROG_TYPE_KPROBE` for the page-cache fill path.
    - **Attach points:** tracepoints `vmscan:mm_vmscan_write_folio`, `vmscan:mm_vmscan_lru_isolate`, and `writeback:writeback_dirty_folio`; kprobes on `shrink_page_list` and `__filemap_add_folio` to correlate evictions with subsequent re-fills for the Postgres data directory's inodes.
    - **Primary data:** eviction rate and re-fill rate scoped to file-backed pages owned by `postgres` PIDs — a direct kernel-side proxy for `shared_buffers` overflow into the OS cache.
- Question - 1. What would be DBA action point even if we alarm it?  Again how to keep historical hits?  3. is there a direct DB way for this?

- **Answer:**
    - **DBA action:** Raise `shared_buffers` (typically toward 25–40% of RAM), raise `effective_cache_size`, scale up the box, partition the hot table, or move cold data to cheaper storage. The alarm is directly actionable.
    - **DBA history:** `pg_stat_statements` keeps per-query I/O history; `pg_stat_io` (PG 16+) gives time-series I/O by backend type; `pg_buffercache` snapshotted hourly to a history table shows what's resident.
    - **DB-only detection:** Yes — `heap_blks_hit / (heap_blks_hit + heap_blks_read)` per table from `pg_statio_user_tables`. Cache hit ratio <99% on a known-hot table = thrashing. This is the textbook approach.
    - **SysAdmin:** `free -h`, `vmstat 1` (`si`/`so` for swap, `bi`/`bo` for block I/O), `cat /proc/pressure/memory` (PSI) to confirm memory is the bottleneck.
    - **Linux dev:** `vmscan` tracepoints add value only when you specifically want to prove *OS-cache* eviction (the double-buffering layer) is happening — distinct from `shared_buffers` overflow.
    - **Architect:** DB-only alarm is sufficient for 90% of cases. eBPF earns its place only when distinguishing "shared_buffers too small" from "OS cache also evicting" matters for the tuning recommendation.
    - **Verdict:** Primary = DB extension. eBPF = optional, for double-buffer-layer attribution.

### 5. Alarm: Connection Storm / Context Switch Flood

- **The Problem:** Excessive connections causing the kernel to spend more time switching processes than doing work.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (Kernel):** High system-wide `context_switches` (via `sched_switch` tracepoint).
        
    - **Signal B (DB):** Rapid spike in `sched_process_fork` events and `active` sessions in `pg_stat_activity`.
        
    - **Alarm Trigger:** Fire if Context Switches per Second exceeds $10,000$ per CPU core while query throughput is declining.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for scheduler + fork accounting; optionally `BPF_PROG_TYPE_KPROBE` on the TCP accept path.
    - **Attach points:** tracepoints `sched:sched_switch` (count voluntary vs involuntary switches per CPU), `sched:sched_process_fork`, and `sched:sched_process_exec`; kprobe on `inet_csk_accept` (or tracepoint `sock:inet_sock_set_state` transitioning to `TCP_ESTABLISHED` on port 5432) to count new client connections at the source.
    - **Primary data:** per-CPU context-switch rate, fork rate scoped to the `postgres` postmaster's children, and TCP accept rate — the leading indicators that precede the storm.
- A direct count of connection via ss, netstat wouldn't do? only useful as fallback? is that correct?

- **Answer:**
    - **DBA:** `pg_stat_activity` and `pg_stat_database.numbackends` give the live count directly. `log_connections` / `log_disconnections` give a connection-event log for free.
    - **SysAdmin:** `ss -tn state established '( sport = :5432 )' | wc -l` is instant and essentially free; conntrack counters give system-wide totals. For a "are we above N connections" alarm, polling `ss` at 1Hz wins outright.
    - **Linux dev:** Polling misses *burst* dynamics — connections opened and torn down between samples. eBPF on `inet_csk_accept` and `sched_process_fork` catches the *rate of churn*, which is the actual cause of context-switch storms; raw count is just the symptom.
    - **Architect:** Split the alarm into two signals: (a) *count* high → `pg_stat_activity` / `ss` (primary, polling); (b) *churn / ctx-switch rate* explodes → eBPF (the causal leg, hard to catch by polling). Fire only when both are true.
    - **Verdict:** You're right — `ss`/`pg_stat_activity` for count. eBPF earns its place only for fork-rate and context-switch churn, not the count itself.

### 6. Alarm: Cascading Lock Queue

- **The Problem:** A single root-blocker PID (often "idle in transaction") causes a massive queue of waiting queries.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (DB):** `pg_locks` showing one PID with a granted lock and dozens of others "waiting."
        
    - **Signal B (Kernel):** Waiting PIDs are in a blocked state with zero CPU and zero I/O activity.
        
    - **Alarm Trigger:** Fire if the "Blocked Query Count" > 10 and the "Root Blocker" PID has been idle for $>1$ second.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for scheduler state; `BPF_PROG_TYPE_UPROBE` on Postgres heavyweight lock entry points.
    - **Attach points:** tracepoint `sched:sched_switch` filtered for `prev_state == TASK_UNINTERRUPTIBLE` (D-state) and `TASK_INTERRUPTIBLE` to identify waiters; uprobe on `LockAcquire` / `ProcSleep` (or USDT `postgresql:lock__wait__start` / `lock__wait__done`) to capture the lock tag and blocker PID without polling `pg_locks`.
    - **Primary data:** an in-kernel graph of `(waiter_pid → blocker_pid, lock_tag, wait_duration)` updated on every wait/wake — eliminates the polling latency that lets short blockers slip past `pg_stat_activity` snapshots.
- What's the linux alternative here? 

- **Answer:**
    - **DBA:** PG already publishes the full dependency graph natively: `pg_locks` joined to `pg_stat_activity`, or the `pg_blocking_pids()` function which literally returns the list of blockers for a given PID. This is the canonical solution and works fine.
    - **SysAdmin:** Linux has *no equivalent* — LWLocks, heavyweight locks, and advisory locks all live in PG shared memory, not in kernel structures. From the OS you can only see "process X is sleeping," which tells you nothing about *what* it's waiting on.
    - **Linux dev:** eBPF + uprobe on `LockAcquire` is the only kernel-visible angle, but it's redundant with the DB views unless you need sub-second resolution.
    - **Architect:** For an alarm that fires on `>1s` blocking, polling `pg_locks` at 1Hz is plenty. eBPF only beats polling when blockers are very short-lived (sub-second), which is rare for the cascading-queue pattern.
    - **Verdict:** No real Linux alternative — DB's `pg_blocking_pids()` is the right tool. eBPF is overkill except for ultra-low-latency detection.

### 7. Alarm: TXID Wraparound (PostgreSQL Only)

- **The Problem:** The database approaches the 2-billion transaction limit, which will force an emergency shutdown to prevent data corruption.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (DB):** `age(datfrozenxid)` exceeds 1 billion (50% of limit).
        
    - **Signal B (DB):** `pg_prepared_xacts` or abandoned replication slots are preventing `datfrozenxid` from advancing.
        
    - **Alarm Trigger:** Fire if (XID Age) is increasing and (Autovacuum Worker Count) is maxed out.

- **Detection model:** **Pure DB extension.** Poll `age(datfrozenxid)` per database every 5 min; enumerate `pg_prepared_xacts` and `pg_replication_slots` for `xmin` blockers. The kernel sees nothing relevant — TXIDs live entirely in PG shared memory and catalog. **eBPF: N/A** (removed after review — the earlier uprobe option was redundant with `pg_stat_statements` attribution).
- What would DBA do? is DB only extension can not detect it? Why even uprobe is needed?

- **Answer:**
    - **DBA actions on alarm:** (1) manual `VACUUM FREEZE` on the highest-age tables, (2) check `pg_prepared_xacts` for abandoned 2PC transactions, (3) check `pg_replication_slots` for inactive slots holding back `xmin`, (4) lower `autovacuum_freeze_max_age`, (5) kill the oldest long-running transaction. Very actionable.
    - **DB-only detection:** Completely sufficient — `SELECT datname, age(datfrozenxid) FROM pg_database;` polled every 5 minutes. RDS, Aurora, and every managed PG do exactly this. The kernel sees nothing relevant.
    - **SysAdmin:** Nothing to add — TXIDs are pure DB state, invisible to the kernel.
    - **Linux dev:** The uprobe on `GetNewTransactionId` was added only to attribute *who* is burning XIDs fastest. But `pg_stat_statements` + `xact_commit` per session derives the same answer from SQL. Not worth the complexity.
    - **Architect:** Drop eBPF from this alarm entirely. Pure DB-extension alarm. The current doc already hedges ("kernel tracepoints contribute essentially nothing"); commit to that fully — remove the uprobe paragraph and mark the eBPF row as N/A in the priority tiering.
    - **Verdict:** Pure DB alarm. Remove eBPF.

### 8. Alarm: Memory Compaction Stall (THP)

- **The Problem:** The Linux kernel stalls query execution to synchronously defragment memory for Transparent Huge Pages.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (Kernel):** Trigger of `do_huge_pmd_anonymous_page` or `compaction` tracepoints.
        
    - **Signal B (Kernel):** Simultaneous 100% CPU spike on a single core with zero DB wait events.
        
    - **Alarm Trigger:** Fire if kernel-level memory compaction events occur for database PIDs.

- **Detection model:** **Configuration audit at startup.** Read `/sys/kernel/mm/transparent_hugepage/enabled` and `/sys/kernel/mm/transparent_hugepage/defrag` once at boot; alarm if either is not `never`. Optional runtime confirmation by reading `/proc/vmstat` `compact_*` and `thp_*` counter deltas every minute — no tracing needed. **eBPF: N/A** (the previous compaction tracepoints were the right *tool* for the wrong *problem* — THP is a misconfiguration, not a runtime workload pattern).
- What should DBA do on alarm? again direct linux level solution could be there? do we need kernel filter?

- **Answer:**
    - **DBA action:** Almost nothing directly — this is a Linux config problem. DBA's job reduces to "ask sysadmin to disable THP." Every PG tuning guide (Crunchy, EDB, AWS) recommends `transparent_hugepage=never` as a baseline.
    - **SysAdmin:** Direct fix is `echo never > /sys/kernel/mm/transparent_hugepage/enabled` plus `defrag=never`, or set via kernel cmdline at boot. Detection is trivial: read `/sys/kernel/mm/transparent_hugepage/enabled` and check whether `[always]` is the active value. `/proc/vmstat` has `compact_*` and `thp_*` counters for runtime evidence.
    - **Linux dev:** Compaction tracepoints add a per-stall *latency distribution*, but the *detection* is just a counter delta from `/proc/vmstat`. No eBPF required to know it's happening.
    - **Architect:** Reframe this as a **configuration-audit check at startup**, not a runtime kernel probe. Extension reads `/sys/kernel/mm/transparent_hugepage/enabled` once at boot and emits a warning if not `never`. After that, the alarm should stay silent forever.
    - **Verdict:** Config-audit alarm, no eBPF. Move to Tier 4 / drop the eBPF block.

### 9. Alarm: Autovacuum "Death Spiral" (PostgreSQL Only)

- **The Problem:** Autovacuum moves too slowly to clean up "dead tuples," causing table bloat and slowing all scans.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (DB):** `n_dead_tup` rising consistently for a table despite autovacuum workers being active.
        
    - **Signal B (Kernel):** Autovacuum worker PIDs showing high I/O wait but low data throughput (`vfs_write` vs `block_rq_complete`).
        
    - **Alarm Trigger:** Fire if Bloat Ratio > 50% and (Writes per Second) by clients is $10\times$ faster than (Reclaims per Second) by workers.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_KPROBE` on the VFS write path and `BPF_PROG_TYPE_TRACEPOINT` on block completion, both PID-filtered to the autovacuum workers (postmaster children whose `comm` starts with `autovacuum`).
    - **Attach points:** kprobes on `vfs_read` / `vfs_write` (logical byte accounting per worker PID); tracepoints `block:block_rq_issue` and `block:block_rq_complete` (physical bytes reaching the device); optional uprobe on `lazy_scan_heap` / `heap_vacuum_rel` (or USDT `postgresql:autovacuum__start` / `autovacuum__done`) to bracket the work window.
    - **Primary data:** ratio of logical-write throughput to physical-write throughput per worker — the gap quantifies how much of the worker's runtime is lost to throttling vs cost-delay sleeps.
- could the user story be something like - n_deaa_tup increasing everyday -- take some actions..again can this be DB only extension?

- **Answer:**
    - **DBA:** Yes, that user story is exactly right. `pg_stat_user_tables.n_dead_tup` polled hourly gives the bloat trend; if it climbs monotonically while `last_autovacuum` is recent, autovacuum can't keep up. Actions: lower per-table `autovacuum_vacuum_scale_factor`, raise `autovacuum_max_workers`, reduce `autovacuum_vacuum_cost_delay`, or partition the table.
    - **DB-only sufficiency:** Fully sufficient for *detection*. `pg_stat_progress_vacuum` (PG 9.6+) shows live vacuum work; `pg_stat_user_tables` gives the trend. pgwatch2, pganalyze, Datadog all detect this with pure SQL.
    - **SysAdmin:** Vacuum I/O is visible in `iostat` filtered by PID, but that's just "vacuum is busy" — no novel info beyond what `pg_stat_progress_vacuum` already says.
    - **Linux dev:** eBPF's *unique* value is partitioning **throttle time** (cost-delay sleeps) from **I/O wait** — which tells the DBA whether the right knob is `autovacuum_vacuum_cost_delay` (workers being throttled) or "buy more IOPS" (storage saturated). DB views can't separate these.
    - **Architect:** DB-extension is the primary detector and triggers most actions. eBPF is a *deep-dive diagnostic* used after the alarm fires to recommend the correct tuning lever.
    - **Verdict:** Primary = DB extension. eBPF = optional diagnostic for "why is vacuum slow" classification.

### 10. Alarm: Silent Index Corruption

- **The Problem:** An index is corrupted, causing queries to return wrong data or revert to full scans without throwing an error.
    
- **Multi-Signal Correlation:**
    
    - **Signal A (DB):** `pg_stat_user_tables` shows `idx_scan` has stopped increasing for a high-volume query.
        
    - **Signal B (Kernel):** Sudden shift from small random reads to massive sequential block reads for the same SQL Hash.
        
    - **Alarm Trigger:** Fire if a query historically using an index switches to sequential I/O patterns without a schema change.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for block-layer geometry; `BPF_PROG_TYPE_UPROBE` for query attribution.
    - **Attach points:** tracepoint `block:block_rq_issue` (captures `sector`, `nr_sector`, `rwbs`, `dev`) — enough to compute seek distance and request size distribution; uprobe on Postgres `index_getnext` / `_bt_first` (or USDT `postgresql:query__start` paired with `query__done`) to tag the I/O burst with a SQL hash and the index OID being scanned.
    - **Primary data:** per-`(query_hash, relation)` distribution of request size and inter-request seek distance — a regime change from small-random to large-sequential is the kernel-side fingerprint of an index that has stopped being used.

### 11. Alarm: Replication Lag Root-Cause (Network vs Apply)

- **The Problem:** A standby falls behind the primary, but `pg_stat_replication` alone can't separate "the WAN is dropping packets" from "the standby's apply worker is saturated."

- **Multi-Signal Correlation:**

    - **Signal A (DB):** `write_lag`, `flush_lag`, and `replay_lag` diverge in `pg_stat_replication` (e.g., flush is current, replay is hours behind).

    - **Signal B (Kernel):** TCP retransmits on the replication peer, *or* the walreceiver PID spends >80% of wall time off-CPU in D-state.

    - **Alarm Trigger:** Fire if `replay_lag > 30s` AND either (retransmits/sec on the replication socket > N) or (walreceiver off-CPU fraction > 0.8).

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` for TCP + scheduler; `BPF_PROG_TYPE_UPROBE` on walsender/walreceiver loops.
    - **Attach points:** tracepoint `tcp:tcp_retransmit_skb` filtered by peer; `sock:inet_sock_set_state` for connection resets; `sched:sched_switch` on walsender / walreceiver PIDs; uprobe on `WalSndLoop` / `XLogWalRcvWrite` (or USDT `postgresql:wal__sender__send__start`) to bracket sender work.
    - **Primary data:** per-replica retransmit rate, send-loop on-CPU vs off-CPU breakdown, and apply-loop iteration latency — cleanly partitions "network slow" from "standby slow."
- Should this be on both primary and secondary? is there a possible DB only solution? assuming postgress offers some observation on cluster?

- **Answer:**
    - **DBA:** Postgres ships the cluster view natively. **Primary side:** `pg_stat_replication` shows per-walsender `write_lag`, `flush_lag`, `replay_lag` — already a 3-way split. **Standby side:** `pg_stat_wal_receiver` plus `pg_last_wal_receive_lsn()` vs `pg_last_wal_replay_lsn()` shows whether the bottleneck is *receive* (network) or *replay* (apply).
    - **Where to deploy:** Both sides — primary owns "what was sent," standby owns "what was applied"; lag is the difference and only the combined view diagnoses cleanly.
    - **DB-only sufficiency:** ~80%. You diagnose most lag from the DB views alone. The remaining 20%: DB views say "everything is fine on both sides" but lag still grows — that's almost always a network problem (TCP retransmits, MTU mismatch, packet loss).
    - **SysAdmin:** `ss -tin` on the replication socket shows RTT, retransmits, cwnd, `Recv-Q`. `nstat -a` for system-wide TCP counters. For the network-branch diagnosis, `ss` covers most of it without eBPF.
    - **Linux dev:** eBPF on `tcp:tcp_retransmit_skb` gives per-event resolution and stack attribution that `ss` polling won't; nice-to-have but not gating.
    - **Architect:** Deploy the agent on both primary and standby. Alarm originates from the primary (it owns the source-of-truth LSN) but pulls standby metrics in. DB views are the primary detector; TCP stats (via `ss` or eBPF) are the network-branch diagnostic.
    - **Verdict:** Both sides, DB-views primary, network probes secondary.

### 12. Alarm: Temp-File Spill (Undersized `work_mem`)

- **The Problem:** Sorts/hashes spill to `base/pgsql_tmp/` because `work_mem` is too small; the query gets 10–100× slower and most dashboards never see it.

- **Multi-Signal Correlation:**

    - **Signal A (DB):** `pg_stat_database.temp_bytes` or `log_temp_files` rising; `EXPLAIN ANALYZE` shows `Sort Method: external merge` or `Hash Batches > 1`.

    - **Signal B (Kernel):** File creations under `base/pgsql_tmp/` attributable to specific backend PIDs.

    - **Alarm Trigger:** Fire if temp bytes per `(pid, query_hash)` exceed `work_mem × K` (e.g., K=2) for more than one occurrence.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` on file syscalls; `BPF_PROG_TYPE_UPROBE` on Postgres' temp-file allocator.
    - **Attach points:** tracepoints `syscalls:sys_enter_openat` and `sys_enter_unlinkat` filtered for paths containing `pgsql_tmp/`; kprobe on `do_filp_open` as a fallback when syscall tracepoints are unavailable; uprobe on `BufFileCreateTemp` / `BufFileWrite` for direct attribution and byte counting without path parsing.
    - **Primary data:** count and byte-size of temp files per `(pid, query_hash)` — surfaces the offending query before user-visible latency.

- **Alarm split — two distinct alarms, two audiences:**
    - **12a — Per-query attribution (eBPF primary):** Tracepoints `syscalls:sys_enter_openat` / `sys_enter_unlinkat` filtered to paths containing `pgsql_tmp/`, plus uprobe on `BufFileCreateTemp` for byte counting. Fires per occurrence with payload `(query_hash, pid, bytes_spilled)`. **Audience:** developers fixing the offending SQL.
    - **12b — Capacity risk (polling, no eBPF):** Poll `du -sh $PGDATA/base/pgsql_tmp/` and `df -h` on the temp tablespace volume. Fires when aggregate footprint > threshold (e.g., 10 GB) or free space < threshold (e.g., 10%). **Audience:** SRE / on-call.

- is this a offending query issue? or it can build up? alarming will change?

- **Answer:**
    - **DBA:** Almost always a *single offending query* — a bad join, an unindexed sort, an aggregation over too much data. Each query that spills creates and deletes its own temp files, so there's no accumulation across queries. But if many concurrent queries spill, the temp dir can fill the disk, which is a *separate* capacity concern.
    - **SysAdmin:** `du -sh $PGDATA/base/pgsql_tmp/` for current footprint; `df -h` on the temp tablespace volume for capacity headroom. Cheap.
    - **Linux dev:** The eBPF hook (`openat` + `BufFileCreateTemp` uprobe) is per-query attribution — answers "which query did this." Doesn't help with capacity.
    - **Architect:** Two distinct alarms, not one:
        1. **Per-query** (eBPF + USDT): "query hash Q spilled N bytes" — fires per occurrence; helps the dev team fix the bad SQL.
        2. **System-wide** (polling): "`pgsql_tmp/` aggregate > X GB" or "free space on temp volume < Y%" — fires on capacity risk.
    - **Verdict:** Split into per-query alarm (eBPF) and capacity alarm (polling). Different alarms, different audiences.

### 13. Alarm: Checkpoint / Bgwriter I/O Storm

- **The Problem:** Periodic latency cliffs whenever the checkpointer flushes dirty pages; classic "every 5 minutes the DB freezes" pattern.

- **Multi-Signal Correlation:**

    - **Signal A (DB):** `pg_stat_bgwriter.checkpoint_write_time` spiking; `checkpoints_req` (forced) >> `checkpoints_timed`; `full_page_writes` traffic peaking right after checkpoint.

    - **Signal B (Kernel):** Burst of `block:block_rq_issue` attributable to the checkpointer / bgwriter PIDs coincides with a rise in commit latency on unrelated backends.

    - **Alarm Trigger:** Fire if checkpointer-attributed write bandwidth > X MB/s for > Y seconds AND P95 commit latency on backends exceeds baseline by 3×.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` on block I/O; `BPF_PROG_TYPE_KPROBE` on the writeback path; optional `BPF_PROG_TYPE_UPROBE` to bracket the checkpoint window.
    - **Attach points:** tracepoints `block:block_rq_issue` / `block:block_rq_complete` filtered by `comm in {checkpointer, background writer}`; kprobe on `sync_file_range`, `vfs_fsync_range`, and `__filemap_fdatawrite_range` for the fsync phase; uprobe on `CheckpointerMain` / `BgBufferSync` to mark phase boundaries.
    - **Primary data:** write bandwidth and fsync latency partitioned by `(checkpointer, bgwriter, backend)` — separates "checkpoint storm" from "client write burst" without guessing.

- **Alarm shape — classification over single-fire:** Don't alarm on a single slow checkpoint. Classify each checkpoint into one of four buckets (using `pg_stat_bgwriter` + the eBPF phase breakdown) and alarm only when one bucket *dominates* over the last N occurrences. The alarm payload carries the dominant classification and the recommended tuning knob, so the DBA gets an actionable recommendation, not just "checkpoint was slow":
    | Bucket | Signal | Recommended action |
    |---|---|---|
    | **Write-phase dominant** | `checkpoint_write_time` >> `checkpoint_sync_time` | Too many dirty pages — raise `checkpoint_completion_target` or lower `max_wal_size`. |
    | **Sync-phase dominant** | `checkpoint_sync_time` dominant | Storage is slow — overlaps with alarm #3 (fsync jitter); investigate WAL device. |
    | **Forced checkpoints** | `checkpoints_req` > `checkpoints_timed` | WAL filling faster than `checkpoint_timeout` — raise `max_wal_size`. |
    | **FPW flood** | High `full_page_writes` traffic right after checkpoint | Checkpoints too frequent — extend `checkpoint_timeout`. |

- How to alarm this? I mean a single instance is enough? or can we do better - each instance can pinpoint some kind of bottleneck?

- **Answer:**
    - **DBA:** A single checkpoint storm is informational; repeated/sustained = bad config or workload mismatch. The alarm needs hysteresis — don't fire on one occurrence. But every individual checkpoint can be *classified* into a specific root cause:
        - `checkpoint_write_time` >> `checkpoint_sync_time` → write phase slow → too many dirty pages; raise `checkpoint_completion_target` or lower `max_wal_size`.
        - `checkpoint_sync_time` dominant → fsync slow → storage problem (overlap with alarm #3).
        - `checkpoints_req` > `checkpoints_timed` → WAL filling faster than checkpoint interval; raise `max_wal_size`.
        - High `full_page_writes` traffic right after → reduce checkpoint frequency.
    - **SysAdmin:** `iostat -x 1` aligned to `pg_stat_bgwriter.checkpoint_*_time` confirms which device gets hammered.
    - **Linux dev:** eBPF partitions write-phase bandwidth vs sync-phase fsync latency at sub-checkpoint granularity, which the catalog only gives as aggregates per checkpoint.
    - **Architect:** Don't alarm on single instance — *classify* each checkpoint into one of the four buckets above, then alarm when one bucket dominates over N occurrences. The alarm payload should carry the classification so the DBA gets a directly-actionable tuning recommendation, not "checkpoint was slow."
    - **Verdict:** Per-instance classification, alarm on dominant-pattern recurrence, payload includes recommended config knob.

### 14. Alarm: Cgroup CPU Throttling (Containerized Postgres)

- **The Problem:** Postgres running under K8s, ECS, or any CFS-quota'd cgroup hits its quota and gets throttled; latency spikes with **zero** signal from inside the database.

- **Multi-Signal Correlation:**

    - **Signal A (Kernel):** `cpu.stat` for the Postgres cgroup shows `nr_throttled` and `throttled_time` accumulating.

    - **Signal B (DB):** Backends show no wait event (or wait_event = `CPU`) yet query latency rises; throughput drops in lockstep with the throttle window.

    - **Alarm Trigger:** Fire if `throttled_time` delta > 50ms per second sustained, and aggregate query latency P95 > baseline × 2.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_KPROBE` on the CFS throttle path; `BPF_PROG_TYPE_TRACEPOINT` on the scheduler; cgroup-aware filtering via `bpf_get_current_cgroup_id()`.
    - **Attach points:** kprobes on `throttle_cfs_rq` and `unthrottle_cfs_rq` to time each throttle window with sub-ms precision; tracepoint `sched:sched_switch` to count involuntary preemptions inside the cgroup; periodic read of `cpu.stat` via a userspace component for cumulative counters.
    - **Primary data:** throttle-window duration histogram per cgroup — proves the kernel held the CPU back, which no `pg_stat_*` view can ever show.

### 15. Alarm: Major Page-Fault Storm

- **The Problem:** Memory pressure forces major page faults (page must be read from disk), producing latency that the buffer-cache hit ratio alone won't predict.

- **Multi-Signal Correlation:**

    - **Signal A (Kernel):** `exceptions:page_fault_user` events with major-fault flag set rise sharply for `postgres` PIDs; `/proc/vmstat` `pgmajfault` accelerates.

    - **Signal B (Kernel):** Direct-reclaim events begin firing, indicating allocations are no longer satisfiable from the free list.

    - **Alarm Trigger:** Fire if major-fault rate > N/sec for `postgres` processes for more than T seconds.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_TRACEPOINT` on faults; `BPF_PROG_TYPE_KPROBE` on the fault slow path; `BPF_PROG_TYPE_TRACEPOINT` on reclaim.
    - **Attach points:** tracepoint `exceptions:page_fault_user` (test `error_code` for the major bit); kprobe + kretprobe on `handle_mm_fault` to measure per-fault latency; tracepoint `vmscan:mm_vmscan_direct_reclaim_begin` / `_end` to mark reclaim windows.
    - **Primary data:** major-fault rate and per-fault latency keyed by PID — an early warning that lands before the OOM killer or before `shared_buffers` spillover becomes catastrophic.

### 16. Alarm: NUMA Cross-Socket Memory Stall

- **The Problem:** `shared_buffers` was allocated on one NUMA node, but backends scheduled on the other socket pay a constant remote-DRAM penalty — a silent ~30% slowdown invisible to all DB-level metrics.

- **Multi-Signal Correlation:**

    - **Signal A (Hardware):** PMU counters show a high ratio of remote-DRAM accesses (`mem_load_uops_retired.remote_dram` / total) for the Postgres workload.

    - **Signal B (Kernel):** `migrate:mm_migrate_pages` firing for Postgres pages; per-backend CPU residency split across sockets.

    - **Alarm Trigger:** Fire if remote-DRAM access ratio > 30% sustained, on a multi-socket host.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_PERF_EVENT` for hardware counters; `BPF_PROG_TYPE_TRACEPOINT` for NUMA balancing.
    - **Attach points:** perf-events on `LLC-load-misses` and `offcore_response` with remote-DRAM response masks (CPU-vendor specific); tracepoints `migrate:mm_migrate_pages` and `sched:sched_swap_numa` to detect kernel-initiated NUMA balancing.
    - **Primary data:** per-PID local-vs-remote DRAM access ratio — the only way to confirm NUMA as the bottleneck instead of generic cache pressure. **Caveat:** PMU access often unavailable in cloud / containerized environments.

### 17. Alarm: Logical Decoding Slot Lag

- **The Problem:** A logical replication slot accumulates WAL because its consumer (CDC pipeline, logical replica) is slow or has disappeared; disk fills silently until the host runs out of space.

- **Multi-Signal Correlation:**

    - **Signal A (DB):** `pg_replication_slots.confirmed_flush_lsn` lags `pg_current_wal_lsn`; `pg_wal_lsn_diff` between them grows monotonically.

    - **Signal B (Kernel):** The walsender for that slot is off-CPU waiting on the consumer socket, *or* the consumer's TCP `recv_q` is full.

    - **Alarm Trigger:** Fire if slot lag bytes > threshold, or growth rate > Y MB/min for > 5 min.

- **Detection model:** **Pure DB extension** + optional `ss` poll. Compute lag per slot via `pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)`; consumer disconnect surfaced by `pg_replication_slots.active = false`. For the "consumer still connected but slow" case, poll `ss -tn` on the walsender socket for `Recv-Q` occupancy. **eBPF: N/A** (`pg_replication_slots` + `ss` together cover the decoder-vs-consumer partition without uprobes).
- is there a DB only way? 

- **Answer:**
    - **DBA:** Yes, almost entirely DB-only. `pg_replication_slots` exposes `confirmed_flush_lsn`, `restart_lsn`, and `active` (is the consumer connected?). Compute lag bytes via `pg_wal_lsn_diff(pg_current_wal_lsn(), confirmed_flush_lsn)`. Polling every minute is sufficient.
    - **SysAdmin:** `ss -tn` on the walsender's socket shows `Recv-Q` — data waiting for the consumer to ack. `lsof` on `pg_wal/` shows which slots are pinning WAL files from recycling. Both are essentially free.
    - **Linux dev:** eBPF on `tcp:tcp_probe` or `ReorderBufferCommit` adds per-iteration decode timing, which helps distinguish "Postgres-side decoder slow" from "consumer slow to ack." But `pg_replication_slots.active` + `ss Recv-Q` together cover this without uprobes.
    - **Architect:** Pure DB-extension alarm. Optional `ss` poll for the "why slow" diagnostic when the consumer is still connected but lagging. Skip eBPF entirely.
    - **Verdict:** DB-only. Drop eBPF for this alarm.

### 18. Alarm: SSL / Auth Handshake Stall

- **The Problem:** New connections take seconds instead of milliseconds because the TLS handshake or pg_hba auth step stalls — typically slow DNS resolution, slow LDAP server, or CPU-bound cipher negotiation.

- **Multi-Signal Correlation:**

    - **Signal A (Kernel/Userspace):** uprobe latency on `SSL_do_handshake` or Postgres `ClientAuthentication` is elevated; DNS syscalls during connect take >100ms.

    - **Signal B (DB):** Surge in backends stuck in `authenticating` state in `pg_stat_activity`; rising rate of failed-login events.

    - **Alarm Trigger:** Fire if median handshake time > 500ms, or P95 auth time > 1s, sustained for > 1 min.

- **eBPF Hook:**
    - **Program type:** `BPF_PROG_TYPE_UPROBE` on TLS and auth library functions; `BPF_PROG_TYPE_KPROBE` on the syscalls auth depends on.
    - **Attach points:** uprobe + uretprobe on `SSL_do_handshake` (libssl) and Postgres `ClientAuthentication` / `auth_peer`; kprobes on `udp_sendmsg` / `udp_recvmsg` for DNS RTT when `pg_hba` uses hostnames; uprobes on libldap (`ldap_sasl_bind_s`) when LDAP auth is configured.
    - **Primary data:** per-connection latency breakdown into `(tls_handshake, dns, ldap, postgres_auth)` segments — pinpoints which step is the bottleneck without guessing.

### 19. Alarm: Idle-in-Transaction Row-Lock Hoarding

- **The Problem:** Backends sit in `idle in transaction` state holding row/object locks for minutes or hours — typically a client-app bug (forgot to commit). Distinct from alarm #6 in time scale and root cause: this is a *single* long-lived offender, not a contention cascade.

- **Multi-Signal Correlation:**

    - **Signal A (DB):** `pg_stat_activity.state = 'idle in transaction'` with `xact_start` older than threshold; `pg_locks` shows the PID holding tuple or relation locks.

    - **Signal B (Kernel):** Backend PID off-CPU for the entire transaction with the client socket idle — proves the wait is on the *client*, not on Postgres internals.

    - **Alarm Trigger:** Fire if `now() - xact_start > 60s` AND state = `idle in transaction`.

- **Detection model:** **Pure DB extension** + config recommendation. Poll `pg_stat_activity WHERE state='idle in transaction' AND now() - xact_start > threshold` every minute; join `pg_locks` to surface what's being held. **Preventive fix:** set `idle_in_transaction_session_timeout` cluster-wide so PG self-heals — alarming is then only for *attribution* (which app keeps doing it). **eBPF: optional**, low priority — adds "client socket has zero bytes pending" attribution (distinguishes "client crashed" from "client slowly working"), but not required to fire the alarm.
- Doesn't DB itself has some king of deadlock prevention that we can lookup?

- **Answer:**
    - **Clarification:** Idle-in-transaction is not a *deadlock* — it's one long-lived transaction holding locks while waiting on a misbehaving client. PG's `deadlock_timeout` only resolves *circular* waits and doesn't apply here. The relevant native mechanism is **`idle_in_transaction_session_timeout`** (PG 9.6+) — set it (e.g., `5min`) and PG automatically kills offending sessions. That is the direct preventive lookup.
    - **DBA:** Best practice is to set `idle_in_transaction_session_timeout` cluster-wide; PG then self-heals. Alarming is still useful — not for prevention but for *attribution* (which app keeps doing this so devs can fix it).
    - **DB-only detection:** Trivial — `SELECT * FROM pg_stat_activity WHERE state='idle in transaction' AND now() - xact_start > '60s';` polled every minute. Plus `pg_locks` to see what's being held.
    - **SysAdmin:** Nothing kernel-side adds detection value here.
    - **Linux dev:** eBPF only adds the "client socket has zero bytes pending" proof — a nice attribution detail (distinguishes "client crashed" from "client is slowly working") but not necessary to *fire* the alarm.
    - **Architect:** Pure DB alarm. Pair with a config recommendation: set `idle_in_transaction_session_timeout`. eBPF is optional for client-crashed-vs-slow attribution.
    - **Verdict:** Pure DB alarm + config recommendation. eBPF optional, low priority.

## Implementation Priority

Alarms are tiered against three axes: **operator impact** (how often this bites in real PG deployments), **eBPF lift** (stable tracepoints are cheap and portable; uprobes on Postgres symbols plus USDT wiring are expensive and Postgres-version-sensitive), and — added after the 4-perspective review of each alarm — the **detection model** (whether eBPF is the primary detector, a confirmer, an optional diagnostic, or N/A and the alarm should be built as a pure DB/polling check).

A key insight from the review: **roughly half the alarms are best built as pure DB-extension or polling checks**, with eBPF reserved either for cases where the kernel signal is genuinely unique (cgroup throttling, fork churn, fsync tail latency, LWLock off-CPU) or as an on-demand diagnostic confirmer for alarms whose detector lives in the catalog. eBPF is not the universal answer; it is the right tool for a specific subset.

### Tier 1 — Ship first (high impact, stable kernel hooks, no PG uprobes required)

| # | Alarm | Detection model | eBPF role |
|---|---|---|---|
| 3 | Fsync Jitter | eBPF (skeleton); `iostat` + `pg_stat_wal` as polling fallback | Primary — for tail-latency fidelity and to scale to shared hosts |
| 5 | Connection Storm | Split: `ss` / `pg_stat_activity` for count, eBPF for churn | Secondary — covers the fork/ctx-switch leg that polling can't catch |
| 12a | Temp-File Spill (per-query) | eBPF + USDT | Primary — per-query attribution |
| 12b | Temp-File Spill (capacity) | `du` / `df` polling | N/A |
| 13 | Checkpoint Storm (classified) | eBPF for phase partition; `pg_stat_bgwriter` for bucket assignment | Primary — enables the classification payload |
| 14 | Cgroup Throttling | eBPF only | Primary — no DB equivalent exists |

This set covers ~60% of real-world PG perf escalations using ~5 stable tracepoints and zero Postgres ABI coupling. It is a credible POC by itself.

### Tier 2 — Flagship features, but require the USDT/uprobe attribution layer

| # | Alarm | Detection model | eBPF role |
|---|---|---|---|
| 1 | Query Plan Regression | DB extension primary (`pg_store_plans` + `pg_stat_statements`) | On-demand confirmer — eBPF runs only when the extension flags a plan flip, to prove I/O moved |
| 2 | LWLock Contention | eBPF primary | Primary — PG views can't see spin-wait at this resolution |
| 9 | Autovacuum Death Spiral | DB extension primary (`pg_stat_user_tables`, `pg_stat_progress_vacuum`) | Diagnostic deep-dive — partitions throttle time from I/O wait to recommend the right knob |
| 11 | Replication Lag | DB views primary (both primary + standby) | Network-branch diagnostic — `tcp:tcp_retransmit_skb` when DB views say "both sides fine" |

These are the *interesting* alarms — the ones DBAs will pay for — but they require building a reusable Postgres symbol-resolution + USDT attach pipeline first. That module is the gating engineering artifact; every Tier 2 alarm consumes it.

**Demoted from Tier 2 after review:** #6 Cascading Lock Queue — `pg_blocking_pids()` plus 1Hz `pg_locks` polling is sufficient for the >1s blocker criterion; eBPF only beats polling for sub-second blockers, which is rare. Moved to Tier 3.

### Tier 3 — Useful additions once Tier 1 + 2 land

| # | Alarm | Detection model | eBPF role |
|---|---|---|---|
| 4 | Buffer Cache Thrash | DB views primary (`pg_statio_user_tables`, `pg_stat_io`) | Optional — only for OS-cache-layer eviction attribution distinct from `shared_buffers` overflow |
| 6 | Cascading Lock Queue | DB primary (`pg_blocking_pids()` + `pg_locks` polling) | Optional — only for sub-second blocker resolution |
| 15 | Major Page Faults | eBPF primary | Primary; overlaps heavily with #4 — consider folding in |
| 19 | Idle-in-Transaction | DB primary + `idle_in_transaction_session_timeout` config | Optional — for "client crashed vs slow" attribution |

### Tier 4 — Drop, defer, or rebuild without eBPF

| # | Alarm | Decision |
|---|---|---|
| 7 | TXID Wraparound | **Pure DB alarm.** eBPF block removed from the doc — catalog polling is the right tool. |
| 8 | THP Compaction Stall | **Configuration audit at startup**, not a runtime tracer. eBPF block removed. |
| 10 | Silent Index Corruption | Collapses into #1's I/O-regime-shift signal. **Recommend fold-in or drop.** |
| 16 | NUMA Cross-Socket Stall | PMU access is gated in most clouds; narrow audience, expensive implementation. **Defer.** |
| 17 | Logical Decoding Lag | **Pure DB alarm** + optional `ss` poll. eBPF block removed. |
| 18 | SSL/Auth Stall | Niche; PgBouncer solves it in practice. **Defer until a customer asks.** |

### Skeleton POC: which single alarm proves the architecture end-to-end?

For the v0 skeleton — eBPF program + loader/orchestrator + PG extension + OTel emission (Python brain deferred) — **Alarm #3 (Fsync Jitter)** is the recommended starting use case.

> **Note on justification:** The 4-perspective review (see the answer block under alarm #3) established that on a single-tenant PG host the *alarm itself* could be solved by polling `iostat` + `pg_stat_wal` at 1Hz. The skeleton choice is justified on **pipeline-development grounds**, not alarm-detection grounds: building #3 with eBPF exercises every component of the full stack (kernel probe → ring buffer → loader correlation → PG extension lookup → OTel histogram emission) with the safest possible kernel hooks. Once that pipeline is proven, every other Tier 1 alarm reuses it by swapping the filter and metric name — including the cases where eBPF really is the only viable detector (#14 cgroup throttling, #2 LWLock contention).

| Component | Role in the v0 skeleton |
|---|---|
| **eBPF program** | Two stable tracepoints (`block:block_rq_issue` + `block:block_rq_complete`) correlated by request struct pointer. Emits `(dev_t, op, latency_ns, pid)` per completion. ~80 lines of Aya. No kprobes, no version-fragile structs. |
| **PG extension** | Single startup job: resolve the `pg_wal` directory's device `major:minor` (via `stat()`) and expose it as a SQL function (`pgsleuth_wal_device()`). Also expose postmaster PID for later PID-filter reuse. |
| **Loader / orchestrator** | At startup, queries the extension to learn the WAL device. Reads BPF ringbuf, filters events by `dev_t == WAL device`, buckets into a histogram, emits OTel. |
| **OTel emission** | Histogram metric `pgsleuth.wal.io.latency` with attributes `{device, op}`. Histogram is the right primitive — most real PG signals are latency distributions, so the skeleton bakes the correct metric shape in from day one. |
| **Brain (deferred)** | Consumes the OTel histogram; runs baseline + anomaly detection; fires the multi-signal alarm. Wire format is already set, so the brain can be added without touching the kernel or DB side. |

**Why this alarm and not another:** #13 (Checkpoint Storm) reuses ~95% of the same BPF code with a `comm` filter — natural *second* alarm but a weaker skeleton because the PG-extension role is almost nothing. #5 (Connection Storm) is counter-only and doesn't exercise the histogram path. #12 (Temp-File Spill) needs path-string matching in BPF, which is fiddly for v0. #14 (Cgroup Throttling) depends on less-stable kprobes and only matters in containerized deployments.

Once the fsync skeleton works, the rest of Tier 1 drops in by changing the PID/device filter and the OTel metric name.

## Conclusion

By moving away from static thresholds and toward **multi-signal correlation**, a DBA can distinguish between "normal high load" and a "threatening system failure." Correlating kernel tracepoints (like `block_rq_issue` and `sched_switch`) with database metadata (like SQL hashes and transaction age) provides the predictive power necessary to stop outages before they occur.