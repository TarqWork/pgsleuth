# **Advanced eBPF-Based Telemetry for PostgreSQL**

##  *Strategies for I/O, Memory Paging, and Process Correlation Using Rust and Aya*

The paradigm of database observability has fundamentally shifted with the maturation of the Extended Berkeley Packet Filter (eBPF). Traditional mechanisms for inspecting internal database states and correlating them with underlying operating system performance often rely on coarse-grained polling of system views or the injection of high-overhead debugging hooks. These historical approaches suffer from significant limitations, particularly in high-throughput database environments where the Heisenberg principle of observability—where the act of measurement fundamentally alters the system's performance—becomes a critical bottleneck. Implementing telemetry via eBPF circumvents these limitations by executing sandboxed, verifiable bytecode directly within the Linux kernel. This allows for near-zero overhead interception of system calls, kernel functions, and user-space tracepoints.

When applied to PostgreSQL, eBPF enables profound visibility into the database's interaction with the Linux kernel, specifically regarding block I/O latencies, memory swapping behavior, and internal lock contention. However, developing an efficient eBPF probe requires overcoming several complex architectural challenges. Relying on naive string-matching algorithms, such as filtering by process name on vfs\_open events, introduces unacceptable overhead and fragility. Furthermore, the use of uprobes (User-Space Probes) often necessitates access to debugging symbols and can induce substantial context-switch overhead that degrades the very database performance the telemetry seeks to measure.

This comprehensive report provides an exhaustive architectural and implementation analysis for a Rust-based eBPF telemetry agent targeting PostgreSQL. It leverages the Aya framework to evaluate highly efficient filtering strategies for isolating PostgreSQL processes, investigates the deployment of kernel tracepoints for I/O and memory paging tracking, evaluates User Statically-Defined Tracing (USDT) as well as custom Rust-based PostgreSQL extensions for context correlation, and establishes a synchronous methodology for correlating operating system Process IDs (PIDs) with PostgreSQL backend processes and their executing SQL statements.

### **Tenets** 

1. Any monitoring agent should not do things that can become a security threat. Hence, if a SQL is accessed, data should not go outside the system.  
2. Any monitoring agent should aspire to be with minimal overhead. Almost zero if possible.   
   

## **Architectural Context: The PostgreSQL Connection Model**

To design an efficient eBPF filtering mechanism, one must first possess a thorough understanding of the process architecture of PostgreSQL. Unlike multi-threaded database engines such as MySQL, PostgreSQL utilizes a distinct process-per-connection architecture. A central daemon, traditionally known as the postmaster, listens for incoming network connections. Upon receiving a connection request, the postmaster invokes the fork() system call to create a dedicated backend process, which is then responsible for handling the entire lifecycle of that specific client session.1

This architectural choice inherently dictates how an eBPF program must identify and filter events. Because each client query executes within a separate process, an eBPF probe cannot simply monitor a single static PID. It must dynamically track a constantly evolving hierarchy of processes. Furthermore, PostgreSQL launches several auxiliary background processes upon startup—such as the checkpointer, background writer, autovacuum launcher, and walwriter.3 A comprehensive telemetry solution must dynamically isolate events originating exclusively from these specific database processes while completely ignoring the ambient noise of other system activities occurring on the host.

Compounding this complexity is the reliance on shared memory. PostgreSQL allocates a massive contiguous block of memory known as shared\_buffers to cache disk blocks, alongside auxiliary shared memory for Write-Ahead Log (WAL) buffers and Lightweight Locks (LWLocks).4 Because multiple distinct processes must access this shared memory concurrently, the operating system's handling of these memory pages—particularly under memory pressure—directly impacts the performance of every active backend process. Measuring this interaction at the kernel level is impossible from within the database itself, necessitating external instrumentation.

## **The Inefficiency of Traditional Filtering and the vfs\_open Dilemma**

The naive approach to process filtering in eBPF often involves inspecting the comm field, which contains the command name associated with the executing task. A common anti-pattern in early eBPF development is to attach a kprobe to a high-frequency system call, such as vfs\_open or do\_sys\_open, extract the task name using a helper function like bpf\_probe\_read\_kernel\_str, and perform a string comparison against the string "postgres".6

This methodology is fundamentally flawed and disastrous in high-throughput environments. String comparison operations consume an excessive number of eBPF instructions. The eBPF kernel verifier strictly limits the complexity of programs to ensure they complete in a bounded amount of time and do not hang the kernel. Complex string matching can easily pollute this restricted instruction limit, leading to program rejection during the load phase. More importantly, executing string comparisons on every single file system open operation across the entire operating system introduces severe latency into the critical path of kernel execution.

Furthermore, process names can be dynamically altered by the application. PostgreSQL dynamically updates its process title to reflect the current activity (e.g., "postgres: idle", "postgres: SELECT"), meaning a simple static string match on the comm field may fail to capture all relevant processes.8 Therefore, more robust, deterministic, and highly efficient alternatives must be employed to isolate PostgreSQL activity.

## **Advanced Process Isolation and Filtering Strategies**

To construct an enterprise-grade eBPF probe, the telemetry agent must discard string parsing in favor of deterministic integer comparisons based on kernel data structures and namespace boundaries. While individual strategies exist, an optimized implementation often combines them.

### **Strategy 1: Dynamic Process Tree Tracking via Scheduler Tracepoints**

The most mathematically precise method for tracking a dynamic process hierarchy is to monitor the operating system's process lifecycle at its inception and termination.1 By attaching eBPF programs to the Linux scheduler's tracepoints, the telemetry agent can maintain a real-time, in-kernel state machine of the PostgreSQL process tree.

The Linux kernel provides specific, highly stable tracepoints for process lifecycle management:

1. **sched:sched\_process\_fork**: Triggered whenever fork() or clone() is invoked, providing access to both the parent and the newly created child process structures.1  
2. **sched:sched\_process\_exec**: Triggered during the execve() system call, when a process replaces its memory space with a new program.1  
3. **sched:sched\_process\_exit**: Triggered when a process terminates, allowing the telemetry agent to perform garbage collection.1

The implementation logic requires initializing an eBPF HashMap mapping a u32 PID to a boolean.11 An eBPF program attached to sched\_process\_fork intercepts every fork event system-wide, checking if the parent PID exists within the map.1 If it does, the child PID is inserted. Terminating PIDs are removed via sched\_process\_exit.12

While perfectly accurate, this approach introduces overhead on heavy-load databases running hundreds of connections. Constantly updating a shared BPF map on every rapid connection and disconnection scales poorly and generates locking overhead within the map mechanisms.

### **Strategy 2: Ancestor Traversal via task\_struct**

An alternative to stateful BPF maps is stateless structural traversal. When a high-frequency kernel event occurs, the eBPF program can dynamically navigate the kernel's internal data structures to determine if the current process descends from the PostgreSQL postmaster.

Every executing thread in the Linux kernel is represented by a task\_struct.13 Within this structure, pointers such as real\_parent link the task to its progenitor. Using the bpf\_get\_current\_task() helper function, an eBPF program obtains a pointer to the current task\_struct and uses bpf\_probe\_read\_kernel() to walk up the parent chain.

While this avoids stateful BPF maps, it is inherently risky. A malicious or poorly optimized filter might dereference the parent pointer recursively indefinitely.13 To satisfy the verifier, the loop traversing the ancestor chain must be bounded. Traversing nested pointers requires sequential memory accesses, incurring CPU cache misses.

### **Strategy 3: Control Group (cGroup) Filtering**

In modern deployments, such as Kubernetes or Docker, the most elegant filtering strategy leverages Linux Control Groups (cGroups).

The eBPF ecosystem provides bpf\_get\_current\_cgroup\_id(), which returns a 64-bit integer representing the unique identifier of the cGroup in which the current task is executing.14 This identifier corresponds directly to the cGroup's file descriptor within the virtual cGroup filesystem.14

The user-space Rust application determines the cGroup ID of the PostgreSQL container during initialization. On any kernel event, the eBPF program simply calls bpf\_get\_current\_cgroup\_id(). If the returned ID matches, the event belongs to PostgreSQL. This provides deterministic, O(1) filtering with virtually zero state-management overhead.1

### **Strategy 4: The Hybrid Approach (Recommended Architecture)**

Given the volatility of maintaining a constantly updating BPF map for hundreds of frequently shifting connection processes, the most optimal architecture is a hybrid approach that sequentially leverages the strengths of all three strategies to minimize latency.

At initialization, the user-space daemon collects static identifiers: the PostgreSQL container's cGroup ID and a static list of base PIDs (the postmaster and core background processes like the checkpointer and walwriter).

The eBPF kernel program evaluates incoming events through a fast-path waterfall logic:

1. **cGroup Fast-Path:** The absolute first check invokes bpf\_get\_current\_cgroup\_id(). Container runtimes heavily rely on cGroups for resource isolation, so if PostgreSQL is running in Docker or Kubernetes, all its descendant processes will natively share this ID.14 If this O(1) check matches, the event is verified immediately. This eliminates the need for any complex PID tracking in containerized environments.  
2. **Static Map Check:** If cGroups are not applicable (e.g., bare-metal legacy environments), the program performs an O(1) lookup in a *static* HashMap. This map only contains the long-lived, primary PostgreSQL PIDs and Group IDs (PGIDs) captured at startup. Because it is rarely updated, it avoids the concurrency bottlenecks of the dynamic sched\_process\_fork tracking strategy.  
3. **Bounded Ancestor Traversal:** If the static lookup fails, the program executes a highly constrained structural traversal. Instead of maintaining every volatile client backend in the map, the eBPF program simply walks up the task\_struct-\>real\_parent chain. The traversal is strictly bounded to a maximum of 2 iterations (using \#pragma unroll). This ensures the verifier passes the program while avoiding deep recursive cache misses. If the parent or grandparent matches a PID in the static map, the process is verified.

This hybrid approach guarantees zero-maintenance overhead in modern container environments while providing a highly efficient, lock-free fallback for heavy-load bare-metal databases.

| Filtering Strategy | Mechanism | Computational Complexity | Best Use Case | Limitations |
| :---- | :---- | :---- | :---- | :---- |
| **String Matching** | bpf\_probe\_read\_kernel\_str | High (String comparison) | Legacy only | Severe CPU overhead, easily breaks. |
| **Dynamic PID Map** | Map updated via sched | O(1) Map Lookup | Simple bare-metal | Map contention overhead on frequently forking databases. |
| **Ancestor Traversal** | Walking task\_struct | O(N) | Environments without maps | Cache misses, verifier loop bounding restrictions. |
| **cGroup Isolation** | bpf\_get\_current\_cgroup\_id() | O(1) Register Access | Containerized / systemd | Ineffective if Postgres is not isolated in a dedicated cGroup. |
| **Hybrid Approach** | cGroup \-\> Static Map \-\> Short Traversal | O(1) mostly | **Enterprise Production** | Slightly more complex eBPF implementation logic. |

## **Extracting Kernel-Level Performance Data Without Uprobes**

Traditional application tracing often relies on uprobes (User-Space Probes) to intercept function calls within application binaries or shared libraries.16 However, uprobes present significant challenges for continuous production telemetry. They require precise memory offsets that change with every compiler revision and binary update. They heavily rely on access to unstripped binaries or DWARF debug symbols, which are frequently omitted from production container images to minimize size.16 Most critically, triggering a uprobe necessitates an expensive context switch from user-space to kernel-space and back, inducing a measurable performance penalty that can skew the latency metrics of high-frequency database operations.17

To avoid uprobes while capturing critical physical metrics like disk I/O and memory swapping, the telemetry architecture must pivot to kernel tracepoints and kprobes, which execute natively within the kernel context.

### **Tracing Block I/O Latency**

PostgreSQL performance is inextricably linked to block storage latency. Analyzing the delay between a backend requesting a read or write operation and the hardware completing it is paramount for diagnosing performance degradation.18 Modern storage, such as NVMe arrays, can handle millions of IOPS, but intermittent micro-stalls at the PCIe or hardware driver level can cause devastating cascading delays in database transaction commits.19

The Linux block layer provides highly stable tracepoints that trace the complete lifecycle of a Block I/O (BIO) request, entirely independent of the user-space process. The two most critical tracepoints for latency measurement are:

1. **block:block\_rq\_issue**: Fired when an I/O request is dispatched by the kernel's I/O scheduler to the physical device driver.20  
2. **block:block\_rq\_complete**: Fired when the hardware interrupts the CPU to signal the completion of the I/O operation.20

The telemetry mechanism involves attaching an eBPF program to block\_rq\_issue. When this tracepoint executes, the program verifies if the initiating PID belongs to PostgreSQL using the cGroup or PID map filtering strategies. If validated, it captures the current nanosecond timestamp using the bpf\_ktime\_get\_ns() helper. It stores this timestamp in a BPF HashMap, keyed by the unique request pointer or the combination of the block device ID and sector number.18

Subsequently, when the block\_rq\_complete tracepoint fires, a second eBPF program retrieves the initial timestamp from the map, calculates the delta against the current time, and generates a latency metric. This allows the user-space telemetry agent to construct high-fidelity histograms of I/O latency distribution specifically for PostgreSQL workloads, exposing micro-stalls and tail latencies that traditional aggregate metrics, such as those provided by iostat, entirely obscure.19

### **Tracing Memory Swapping Mechanics**

Memory swapping occurs when the Linux kernel, facing severe memory pressure, is forced to evict pages from physical RAM to secondary storage.22 In the context of PostgreSQL, swapping is catastrophic. If the kernel swaps out segments of PostgreSQL's shared\_buffers or the anonymous memory of active backend processes, subsequent accesses will trigger massive latency spikes as the CPU stalls waiting for synchronous disk reads.23

The Linux kernel categorizes memory pages primarily into file-backed pages (the page cache) and anonymous pages (process heap and stack data).25 While file-backed pages can simply be discarded and reread from their source files on the filesystem, anonymous pages do not have a backing file; they must be explicitly written out to a dedicated swap device or swap file.26

#### **Tracepoints for Swap-Out (Page Eviction)**

To trace the exact moment the kernel forces a PostgreSQL page to disk, the telemetry agent must target the Virtual Memory Scanner subsystem (vmscan). The kernel thread kswapd continuously evaluates memory health, maintaining Active and Inactive Least Recently Used (LRU) lists. When available memory drops below a predefined watermark, kswapd begins asynchronously scanning and reclaiming pages.23

The historical kernel function pageout or the tracepoint mm\_vmscan\_writepage has been deprecated in recent kernels (e.g., Linux 6.1 and later) as the kernel transitions to a folio-based memory architecture.30 The modern tracepoint to monitor is **mm\_vmscan:mm\_vmscan\_write\_folio** (or attaching a kprobe to mm\_vmscan\_write\_folio).31

By attaching an eBPF program to this tracepoint, the telemetry agent can detect when the kernel is actively pushing pages out to the swap cache. However, a significant correlation challenge exists here: because kswapd operates asynchronously as an independent kernel thread, the executing PID during a swap-out event will not match the PostgreSQL backend PID.23 Therefore, tracking swap-outs precisely to a specific PostgreSQL process requires deep inspection of the page's mapping or monitoring the system's global anonymous swap rate, correlating it in time with PostgreSQL memory allocation spikes.23

#### **Tracepoints for Swap-In (Page Fault Stalls)**

While swap-outs happen asynchronously, swap-ins have a direct and synchronous impact on PostgreSQL performance. When a backend attempts to access a memory address that has been swapped out, the CPU triggers a major page fault. The kernel must immediately halt the execution of the database process, locate the page in the swap cache or on the physical swap disk, and issue a synchronous read request to bring the data back into RAM.24

This complex sequence involves the architecture-specific do\_page\_fault handler routing to handle\_mm\_fault, which eventually determines the page is missing and calls do\_swap\_page.34 The do\_swap\_page function ultimately invokes the crucial routine **read\_swap\_cache\_async**.24

By attaching a kprobe to read\_swap\_cache\_async, the telemetry agent can precisely capture the exact moment a PostgreSQL backend process—which is actively executing and easily identified via the PID filter—stalls due to a major page fault.24 Correlating the duration of this specific function call with the overall transaction execution time provides definitive, mathematically provable root-cause analysis for query degradation caused by memory starvation.7

| Kernel Operation | Recommended Mechanism | Primary eBPF Target | Objective for PostgreSQL Telemetry |
| :---- | :---- | :---- | :---- |
| **I/O Issue** | Tracepoint | block/block\_rq\_issue | Record exact start timestamp of block request. |
| **I/O Complete** | Tracepoint | block/block\_rq\_complete | Calculate hardware response latency to identify PCIe/NVMe stalls. |
| **Swap Out** | Tracepoint / Kprobe | vmscan/mm\_vmscan\_write\_folio | Detect eviction of anonymous pages under system memory pressure. |
| **Swap In** | Kprobe | read\_swap\_cache\_async | Measure major page fault stall durations impacting active queries. |

## **Exploiting User Statically-Defined Tracing (USDT)**

While kernel tracepoints reveal the physical interaction between PostgreSQL and the underlying hardware, they lack semantic awareness of the database operations. A block I/O request does not inherently indicate whether PostgreSQL is reading an index, writing a Write-Ahead Log (WAL), or performing a massive sequential scan. To bridge this semantic gap without relying on fragile uprobes, the architecture must leverage User Statically-Defined Tracing (USDT).36

### **The Mechanics of USDT**

USDT represents an explicit, stable tracing interface provided directly by the application developers. Originally derived from Sun Microsystems' DTrace utility, USDT probes are static hooks compiled directly into the application binary.36 These probes are embedded within the Executable and Linkable Format (ELF) binary in a specialized section named .note.stapsdt. This section acts as a manifest, recording the probe's provider name, its logical name, its physical memory location within the executable, and the location and types of its arguments.17

Because they are statically defined at compile time, USDT probes act like tracepoints for user-space applications. When disabled, they execute as a virtually zero-overhead NOP (No Operation) instruction within the application's code path.17 When an eBPF program attaches to a USDT probe, the Linux kernel dynamically patches the NOP instruction with a breakpoint interrupt (e.g., an INT 3 instruction on x86 architectures) to immediately trigger the registered eBPF handler.17 This mechanism provides incredible stability across software versions, making the telemetry architecture largely immune to the symbol-stripping and offset-shifting problems that perpetually plague uprobes.16

### **Evaluating PostgreSQL's Built-in USDT Probes**

The core development team of PostgreSQL has extensively instrumented the database engine with standard trace points designed specifically for DTrace and SystemTap. However, these probes are not compiled into the default source binaries to avoid even the most microscopic overhead; the source code must be explicitly compiled using the \--enable-dtrace configuration flag.38

Fortunately, maintainers of major Linux distributions recognize the critical value of this telemetry. The official PostgreSQL Global Development Group (PGDG) packages for Debian and Ubuntu, distributed via the apt.postgresql.org repository, are consistently built with the \--enable-dtrace flag enabled for Linux targets.38 Similarly, Red Hat Enterprise Linux (RHEL), AlmaLinux, and Rocky Linux RPM specifications for PostgreSQL include macros that enable DTrace support depending on the specific OS version.38 Consequently, production environments utilizing standard distribution packages can frequently leverage USDT observability out of the box without requiring custom compilation.

PostgreSQL exposes dozens of highly valuable USDT probes. A selection of the most critical probes for performance telemetry includes:

| Probe Name | Arguments | Telemetry Application |
| :---- | :---- | :---- |
| query-start | (const char \*) query string | Pinpoints the exact start of query execution, capturing the raw SQL text before parser processing. 38 |
| query-done | (const char \*) query string | Marks the end of execution; calculating the delta with query-start yields total query execution time. 38 |
| transaction-start | (LocalTransactionId) | Tracks the inception of a transaction, allowing calculation of transaction throughput and duration. 38 |
| lwlock-acquire | (char \*) tranche, (LWLockMode) mode | Monitors internal Lightweight Lock contention, which protects critical shared memory structures like buffer mapping and WAL insertion. 5 |
| buffer-read-start | (ForkNumber, BlockNumber, Oid,...) | Tracks logical block reads initiated by the backend before they potentially hit the OS filesystem cache. 38 |
| wal-insert | (unsigned char, unsigned char) | Analyzes the rate and computational overhead of Write-Ahead Log record generation. 38 |

### **Extracting USDT Arguments in eBPF**

To fully utilize these probes, the eBPF program must dynamically read the arguments passed to the USDT macro by the PostgreSQL C code. For example, the query-start probe passes a const char \* pointing to the raw SQL query string as its very first argument (arg0).38

When attaching to a USDT probe via an eBPF framework, the arguments must be carefully and safely extracted. Because the query string resides in the virtual memory space of the PostgreSQL user-space process, the eBPF program cannot dereference the pointer directly. Doing so would violate the strict memory safety rules enforced by the kernel and trigger an immediate fault, potentially terminating the eBPF program. Instead, the program must utilize specialized helper functions such as bpf\_probe\_read\_user\_str or bpf\_probe\_read\_user\_str\_bytes.9 These functions safely copy the string data from user-space memory across the privilege boundary into the eBPF stack or a predefined BPF map.9

By utilizing the bpf\_usdt\_readarg helper (or equivalent BTF mechanisms) to locate the pointer, and bpf\_probe\_read\_user\_str to extract the payload, the telemetry agent can capture the exact SQL statement executing at any given moment, with negligible overhead and complete architectural stability.43

## **Correlating OS Events with PostgreSQL Context**

The ultimate objective of a comprehensive database telemetry system is the unification of context. An administrator or automated agent observing a sudden spike in block I/O latency or a wave of page swap-ins must be able to attribute that system-level strain directly to a specific database action.45 This requires seamlessly correlating the Operating System PID—captured by the kernel tracepoints—with the internal PostgreSQL backend state and the executing SQL query.

### **The Semantic Gap and pg\_stat\_activity**

When an eBPF program attaches to block\_rq\_issue or read\_swap\_cache\_async, it captures the OS-level thread group ID (tgid) via the bpf\_get\_current\_pid\_tgid() helper. However, standard PostgreSQL diagnostic methodologies rely on internal system catalog views, most prominently pg\_stat\_activity.8

pg\_stat\_activity is a critical administrative view that exposes real-time information about all active sessions currently connected to the database.8 It contains fields such as pid (the backend process ID), usename (the authenticated database user), client\_addr (the source IP address of the connection), state (whether the session is active, idle, or idle in transaction), and query (the text of the currently executing SQL command, which may be truncated based on the track\_activity\_query\_size parameter).3 Because PostgreSQL utilizes a strict process-per-client model, the pid column exposed in pg\_stat\_activity is mathematically identical to the OS-level PID.45

### **Correlation Mechanisms: Out-of-Band vs. In-Band**

There are three primary architectural methods for bridging the semantic gap between kernel metrics and PostgreSQL activity, each with varying levels of complexity and performance.

#### **Method 1: Traditional Out-of-Band Database Querying**

When the user-space telemetry agent detects anomalous kernel behavior—such as a process exhibiting excessive swap-in stall times—it can open an asynchronous database connection and execute a SQL query against pg\_stat\_activity, filtering by the offending PID.48

While simple to implement, this approach is inherently flawed in high-stress production scenarios. If the database is experiencing severe lock contention or I/O starvation, attempting to establish a new TCP connection and execute a query may time out or actively exacerbate the underlying problem.46 Furthermore, because database queries often execute in milliseconds, the backend may have completed the offending query and cleared its state before the out-of-band query resolves over the network, leading to a critical mismatch in attribution.

#### **Method 2: In-Band Correlation via eBPF Maps (USDT Dependent)**

If the PostgreSQL binary is compiled with \--enable-dtrace, the agent can rely entirely on the eBPF layer to maintain state.

1. **State Capture:** When a client issues a query, the query-start USDT probe fires. The attached eBPF program captures the OS PID and safely copies the raw SQL text, writing this association into a central BPF HashMap.43  
2. **Metric Association:** When a subsequent kernel event occurs (e.g., a major page fault), the eBPF tracepoint retrieves the current OS PID, performs an O(1) lookup in the map, and bundles the physical metric with the SQL string.43  
3. **State Cleanup:** When the query finishes, the query-done USDT probe fires, and the corresponding eBPF program removes the PID from the map to maintain pristine state hygiene.43

This method completely bypasses PostgreSQL's internal locking mechanisms, but it relies heavily on the availability of USDT probes, which are not universally enabled across all custom environments.

#### **Method 3: The Hybrid Agent-Extension Architecture (Highly Recommended)**

To overcome the latency limitations of standard out-of-band polling while avoiding a strict dependency on USDT availability, a cutting-edge hybrid approach can be employed. This architecture pairs the Rust eBPF agent with a custom, Rust-based PostgreSQL extension.

1. **Event Harvesting:** eBPF kprobes and tracepoints monitor the system for "interesting" OS PIDs—specifically those causing long-running block I/O, triggering major page fault swap-ins, or consuming deep CPU cycles.  
2. **Short-Duration Buffering:** These events are streamed via a BPF Ring Buffer to the user-space Rust agent. The agent maintains a very short-lived cache (e.g., 10-50ms) of these PIDs and their corresponding physical events.  
3. **Fast-Path IPC Signaling:** Instead of opening a standard PostgreSQL connection, the Rust agent communicates via a low-latency Unix Domain Socket directly to a custom PostgreSQL extension.  
4. **Rust-Based PostgreSQL Extension (pgrx):** This companion extension is written in Rust utilizing the pgrx framework. It registers itself as a PostgreSQL Background Worker (bgworker) upon database startup, allowing it to run within the PostgreSQL memory space safely and autonomously.  
5. **Direct Shared Memory Snapshotting:** Because the extension operates natively inside PostgreSQL, it bypasses the SQL parser, planner, and executor entirely. When signaled with an offending PID by the agent, the extension uses pgrx's pg\_sys bindings to directly access the BackendStatusArray in PostgreSQL's shared memory. This is the exact internal C-structure that powers the pg\_stat\_activity view.  
6. **Microsecond Extraction:** The extension instantly snapshots the query string, user, and state for that specific PID in microseconds, returning it over the socket to the user-space agent to be correlated with the eBPF physical metrics.

This hybrid approach represents the optimal balance for modern production systems. It guarantees that the agent captures highly ephemeral query data before it is ejected from shared memory, it requires zero SQL overhead or TCP connection pooling, and it operates safely outside the critical path of the database's transactional workload.

## **Implementation Architecture: Rust and the Aya Framework**

The development of eBPF programs has traditionally been heavily dominated by the C language and frameworks such as BCC (BPF Compiler Collection) or libbpf. While powerful, these frameworks often require distributing heavy compiler toolchains, such as Clang and LLVM, to production servers for Just-In-Time (JIT) compilation. Alternatively, they rely on complex, error-prone C-to-user-space bindings that complicate deployment and maintenance.1

The introduction of the Rust programming language and the Aya framework modernizes this paradigm. Aya is a pure-Rust eBPF library built from the ground up with a focus on operability, memory safety, and developer experience.51 It does not rely on libbpf or BCC, utilizing only the standard libc crate to execute the necessary system calls for loading eBPF bytecode.51

### **The Advantages of Aya for Database Telemetry**

Writing both the user-space daemon and the eBPF kernel component in Rust provides unparalleled memory safety and concurrency control, natively leveraging asynchronous runtimes like tokio for efficient I/O processing.51 The eBPF kernel component is written in restricted Rust (using the \#\!\[no\_std\] and \#\!\[no\_main\] attributes to comply with kernel limitations), allowing developers to share struct definitions natively between kernel and user-space code without writing fragile C-header wrappers.12

A critical advantage of Aya is its deep integration with BTF (BPF Type Format). BTF enables the Compile-Once, Run-Everywhere (CO-RE) methodology. This allows an eBPF program compiled on a developer's machine against one kernel version to be loaded onto a completely different production kernel version without recompilation.51 Aya transparently handles the complex relocation of structure offsets during the load phase. This is crucial when the telemetry agent must traverse kernel structures like task\_struct for process filtering, as the internal memory layout of these structures varies wildly between minor Linux kernel releases.

To interact with internal kernel structures, Aya provides a dedicated utility named aya-tool. This utility parses the BTF information of the currently running kernel and automatically generates safe Rust bindings for the kernel types.55 By running a command such as aya-tool generate task\_struct \> vmlinux.rs, developers gain native Rust access to the precise memory layout of the kernel, significantly accelerating development and ensuring type safety across the kernel-user boundary.55

### **Communication Mechanisms: BPF Map Selection**

The fundamental bridge between the eBPF programs running in the restricted kernel context and the Rust observability daemon running in user space is constructed using BPF Maps.11 Aya provides highly idiomatic Rust abstractions for these map types.11

For a complex PostgreSQL telemetry agent, selecting the correct map type is vital for performance and verifier compliance:

| BPF Map Type | Aya Implementation | Telemetry Use Case | Technical Rationale |
| :---- | :---- | :---- | :---- |
| **Hash Map** | HashMap | Process Tree Tracking & Active Query State | Provides O(1) lookups based on a key (PID). Crucial for correlating query-start state with subsequent kernel tracepoints.11 |
| **Per-CPU Array** | PerCpuArray | User-Space String Extraction Scratchpad | The eBPF verifier enforces a strict 512-byte stack limit. Extracting large SQL queries (e.g., 1024 bytes) from USDT probes requires dynamic memory. A PerCpuArray of size 1 provides lockless, CPU-local heap memory to temporarily hold the string before transmission.9 |
| **Ring Buffer** | RingBuf | Event Streaming to User Space | Replaces the legacy PerfEventArray. The modern RingBuf is a multi-producer, single-consumer queue that guarantees strict event ordering and minimizes memory overhead, making it the optimal choice for streaming high-throughput I/O and page fault events.10 |

### **Resolving USDT with Aya**

Integrating USDT directly with Aya currently requires bridging the gap between reading the .note.stapsdt ELF sections embedded in the PostgreSQL binary and instructing the kernel to attach the eBPF program.17 While legacy tools like bcc provide python wrappers for this complexity, an idiomatic Rust implementation utilizes ecosystem crates such as usdt to parse the probe definitions natively.58

The user-space Aya daemon must execute a specific sequence: locate the executing PostgreSQL binary on the filesystem, parse the ELF notes to find the exact memory address offsets of the target probes (e.g., query-start and lwlock-acquire), and then instruct the Linux perf subsystem to attach uprobe handlers to those specific calculated addresses.17 Once attached, the eBPF program written in Aya executes, utilizing the bpf\_probe\_read\_user helpers to extract the context safely into its RingBuf payload, thereby completing the telemetry loop.

## **Conclusion**

The synthesis of eBPF, Rust, and PostgreSQL presents a quantum leap in the discipline of database observability. By discarding high-overhead, polling-based mechanisms and naive string-matching filters in favor of deterministic cGroup isolation and tracepoint-based process tree tracking, the telemetry agent's performance footprint is reduced to near absolute zero.

The strategic avoidance of user-space probes for system-level metrics, in favor of highly stable kernel tracepoints (block\_rq\_issue, block\_rq\_complete, mm\_vmscan\_write\_folio, read\_swap\_cache\_async), guarantees deep visibility into the exact moments that hardware limitations and memory starvation constrain database performance. Furthermore, utilizing a Hybrid Agent-Extension architecture or statically defined USDT probes acts as the vital semantic bridge, allowing abstract kernel latencies—such as micro-stalls during a major page fault—to be mapped instantaneously and automatically to individual, high-level SQL statements. Constructed upon the strict memory safety and Compile-Once-Run-Everywhere capabilities of the Aya framework alongside pgrx integrations, this architectural blueprint delivers a resilient, comprehensive, and hyper-efficient telemetry pipeline suitable for the most demanding production database environments.

#### **Works cited**

1. How to Track Process Lifecycle Events with eBPF \- OneUptime, accessed on May 11, 2026, [https://oneuptime.com/blog/post/2026-01-07-ebpf-process-lifecycle-tracking/view](https://oneuptime.com/blog/post/2026-01-07-ebpf-process-lifecycle-tracking/view)  
2. eBPF Tracing of PostgreSQL Spinlocks \- Jan Nidzwetzki, accessed on May 11, 2026, [https://jnidzwetzki.github.io/2026/02/08/postgresql-spinlocks.html](https://jnidzwetzki.github.io/2026/02/08/postgresql-spinlocks.html)  
3. Documentation: 18: 27.2. The Cumulative Statistics System \- PostgreSQL, accessed on May 11, 2026, [https://www.postgresql.org/docs/current/monitoring-stats.html](https://www.postgresql.org/docs/current/monitoring-stats.html)  
4. Documentation: 9.1: Managing Kernel Resources \- PostgreSQL, accessed on May 11, 2026, [https://www.postgresql.org/docs/9.1/kernel-resources.html](https://www.postgresql.org/docs/9.1/kernel-resources.html)  
5. Finding the root cause of locking problems in Postgres \- pganalyze, accessed on May 11, 2026, [https://pganalyze.com/blog/5mins-postgres-find-cause-locking-problems](https://pganalyze.com/blog/5mins-postgres-find-cause-locking-problems)  
6. Helper Function 'bpf\_probe\_read\_kernel\_str' \- eBPF Docs, accessed on May 11, 2026, [https://docs.ebpf.io/linux/helper-function/bpf\_probe\_read\_kernel\_str/](https://docs.ebpf.io/linux/helper-function/bpf_probe_read_kernel_str/)  
7. Program Type 'BPF\_PROG\_TYPE\_KPROBE' \- eBPF Docs, accessed on May 11, 2026, [https://docs.ebpf.io/linux/program-type/BPF\_PROG\_TYPE\_KPROBE/](https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_KPROBE/)  
8. Monitoring Active Queries in PostgreSQL: Real-Time Performance Diagnostics Using pg\_stat\_activity | by Jeyaram Ayyalusamy | Medium, accessed on May 11, 2026, [https://medium.com/@jramcloud1/monitoring-active-queries-in-postgresql-real-time-performance-diagnostics-using-pg-stat-activity-cd707a42aee7](https://medium.com/@jramcloud1/monitoring-active-queries-in-postgresql-real-time-performance-diagnostics-using-pg-stat-activity-cd707a42aee7)  
9. Tracepoints \- Building eBPF Programs with Aya, accessed on May 11, 2026, [https://aya-rs.dev/book/programs/tracepoints](https://aya-rs.dev/book/programs/tracepoints)  
10. eBPF Tutorial by Example 8: Monitoring Process Exit Events, Print Output with Ring Buffer, accessed on May 11, 2026, [https://medium.com/@yunwei356/ebpf-tutorial-by-example-8-monitoring-process-exit-events-print-output-with-ring-buffer-73291d5e3a50](https://medium.com/@yunwei356/ebpf-tutorial-by-example-8-monitoring-process-exit-events-print-output-with-ring-buffer-73291d5e3a50)  
11. aya::maps \- Rust \- Docs.rs, accessed on May 11, 2026, [https://docs.rs/aya/latest/aya/maps/index.html](https://docs.rs/aya/latest/aya/maps/index.html)  
12. How to Write eBPF Programs in Rust with Aya \- OneUptime, accessed on May 11, 2026, [https://oneuptime.com/blog/post/2026-01-07-ebpf-rust-aya/view](https://oneuptime.com/blog/post/2026-01-07-ebpf-rust-aya/view)  
13. Programmable System Call Security with eBPF \- arXiv, accessed on May 11, 2026, [https://arxiv.org/pdf/2302.10366](https://arxiv.org/pdf/2302.10366)  
14. Helper Function 'bpf\_get\_current\_cgroup\_id' \- eBPF Docs, accessed on May 11, 2026, [https://docs.ebpf.io/linux/helper-function/bpf\_get\_current\_cgroup\_id/](https://docs.ebpf.io/linux/helper-function/bpf_get_current_cgroup_id/)  
15. How to get cgroup path of task in an eBPF program? \- Stack Overflow, accessed on May 11, 2026, [https://stackoverflow.com/questions/62188909/how-to-get-cgroup-path-of-task-in-an-ebpf-program](https://stackoverflow.com/questions/62188909/how-to-get-cgroup-path-of-task-in-an-ebpf-program)  
16. An eBPF overview, part 5: Tracing user processes \- Collabora, accessed on May 11, 2026, [https://www.collabora.com/news-and-blog/blog/2019/05/14/an-ebpf-overview-part-5-tracing-user-processes/](https://www.collabora.com/news-and-blog/blog/2019/05/14/an-ebpf-overview-part-5-tracing-user-processes/)  
17. USDT Probes: A Deep Dive \- Polar Signals, accessed on May 11, 2026, [https://www.polarsignals.com/blog/posts/2025/12/10/usdt-deep-dive](https://www.polarsignals.com/blog/posts/2025/12/10/usdt-deep-dive)  
18. How to Analyze Disk I/O Performance with eBPF \- OneUptime, accessed on May 11, 2026, [https://oneuptime.com/blog/post/2026-01-07-ebpf-disk-io-analysis/view](https://oneuptime.com/blog/post/2026-01-07-ebpf-disk-io-analysis/view)  
19. Optimizing eBPF I/O latency accounting when running 37M IOPS on a 384-CPU server, accessed on May 11, 2026, [https://tanelpoder.com/posts/optimizing-ebpf-biolatency-accounting/](https://tanelpoder.com/posts/optimizing-ebpf-biolatency-accounting/)  
20. Expert Guide to eBPF Tracing in Linux, accessed on May 11, 2026, [https://linuxgd.medium.com/expert-guide-to-ebpf-tracing-in-linux-a1ca43bd7249](https://linuxgd.medium.com/expert-guide-to-ebpf-tracing-in-linux-a1ca43bd7249)  
21. iovisor/bcc: BCC \- Tools for BPF-based Linux IO analysis, networking, monitoring, and more \- GitHub, accessed on May 11, 2026, [https://github.com/iovisor/bcc](https://github.com/iovisor/bcc)  
22. Swap In/Out · GitBook, accessed on May 11, 2026, [https://casys-kaist.github.io/pintos-kaist/project3/swapping.html](https://casys-kaist.github.io/pintos-kaist/project3/swapping.html)  
23. Need explanation on RHEL kernels behaviour about cache, shared, swap and anonymous memory segments \- Red Hat Customer Portal, accessed on May 11, 2026, [https://access.redhat.com/solutions/7135054](https://access.redhat.com/solutions/7135054)  
24. Chapter 11 Swap Management \- The Linux Kernel Archives, accessed on May 11, 2026, [https://www.kernel.org/doc/gorman/html/understand/understand014.html](https://www.kernel.org/doc/gorman/html/understand/understand014.html)  
25. The Anonymous Reverse Mapping – An Introduction | linux \- Oracle Blogs, accessed on May 11, 2026, [https://blogs.oracle.com/linux/anonymous-reverse-mapping](https://blogs.oracle.com/linux/anonymous-reverse-mapping)  
26. What parts of a process memory can get swapped? \- Unix & Linux Stack Exchange, accessed on May 11, 2026, [https://unix.stackexchange.com/questions/663425/what-parts-of-a-process-memory-can-get-swapped](https://unix.stackexchange.com/questions/663425/what-parts-of-a-process-memory-can-get-swapped)  
27. What has to happen with Unix virtual memory when you have no swap space, accessed on May 11, 2026, [https://utcc.utoronto.ca/\~cks/space/blog/unix/NoSwapConsequence](https://utcc.utoronto.ca/~cks/space/blog/unix/NoSwapConsequence)  
28. Memory Swapping in Linux \- openEuler, accessed on May 11, 2026, [https://www.openeuler.org/en/blog/liqunsheng/2020-11-26-swap.html](https://www.openeuler.org/en/blog/liqunsheng/2020-11-26-swap.html)  
29. mm/vmscan.c \- kernel/msm \- Git at Google \- Android GoogleSource, accessed on May 11, 2026, [https://android.googlesource.com/kernel/msm/+/android-msm-marlin-3.18-nougat-dr1/mm/vmscan.c](https://android.googlesource.com/kernel/msm/+/android-msm-marlin-3.18-nougat-dr1/mm/vmscan.c)  
30. Swapping out a specific page in LINUX KERNEL \- Stack Overflow, accessed on May 11, 2026, [https://stackoverflow.com/questions/42534519/swapping-out-a-specific-page-in-linux-kernel](https://stackoverflow.com/questions/42534519/swapping-out-a-specific-page-in-linux-kernel)  
31. tracepoint:vmscan:mm\_vmscan\_writepage no longer available · Issue \#28 · brendangregg/bpf-perf-tools-book \- GitHub, accessed on May 11, 2026, [https://github.com/brendangregg/bpf-perf-tools-book/issues/28](https://github.com/brendangregg/bpf-perf-tools-book/issues/28)  
32. trace-vmscan-postprocess.pl, accessed on May 11, 2026, [https://www.kernel.org/doc/Documentation/trace/postprocess/trace-vmscan-postprocess.pl](https://www.kernel.org/doc/Documentation/trace/postprocess/trace-vmscan-postprocess.pl)  
33. Understanding page faults and memory swap-in/outs: when should you worry? \- Scout APM, accessed on May 11, 2026, [https://www.scoutapm.com/blog/understanding-page-faults-and-memory-swap-in-outs-when-should-you-worry](https://www.scoutapm.com/blog/understanding-page-faults-and-memory-swap-in-outs-when-should-you-worry)  
34. Explanation of writepage/readpage in Linux swapping. \- LinuxQuestions.org, accessed on May 11, 2026, [https://www.linuxquestions.org/questions/linux-kernel-70/explanation-of-writepage-readpage-in-linux-swapping-4175465087/](https://www.linuxquestions.org/questions/linux-kernel-70/explanation-of-writepage-readpage-in-linux-swapping-4175465087/)  
35. ebpf/examples/README.md at main · cilium/ebpf \- GitHub, accessed on May 11, 2026, [https://github.com/cilium/ebpf/blob/main/examples/README.md](https://github.com/cilium/ebpf/blob/main/examples/README.md)  
36. Using user-space tracepoints with BPF \- LWN.net, accessed on May 11, 2026, [https://lwn.net/Articles/753601/](https://lwn.net/Articles/753601/)  
37. Getting BPF programs working with USDT probes (Dtrace) in Linux \- Stack Overflow, accessed on May 11, 2026, [https://stackoverflow.com/questions/62641551/getting-bpf-programs-working-with-usdt-probes-dtrace-in-linux](https://stackoverflow.com/questions/62641551/getting-bpf-programs-working-with-usdt-probes-dtrace-in-linux)  
38. Documentation: 18: 27.5. Dynamic Tracing \- PostgreSQL, accessed on May 11, 2026, [https://www.postgresql.org/docs/current/dynamic-trace.html](https://www.postgresql.org/docs/current/dynamic-trace.html)  
39. Documentation: 18: 17.3. Building and Installation with Autoconf and Make \- PostgreSQL, accessed on May 11, 2026, [https://www.postgresql.org/docs/current/install-make.html](https://www.postgresql.org/docs/current/install-make.html)  
40. Apt \- PostgreSQL wiki, accessed on May 11, 2026, [https://apt.postgresql.org/](https://apt.postgresql.org/)  
41. Changelog \- Debian \-- Packages, accessed on May 11, 2026, [https://packages.debian.org/changelog:postgresql-common](https://packages.debian.org/changelog:postgresql-common)  
42. postgresql/postgresql.spec at master · sclorg/postgresql \- GitHub, accessed on May 11, 2026, [https://github.com/sclorg/postgresql/blob/master/postgresql.spec](https://github.com/sclorg/postgresql/blob/master/postgresql.spec)  
43. How to Trace System Calls and Functions with eBPF (bpftrace, bcc) \- OneUptime, accessed on May 11, 2026, [https://oneuptime.com/blog/post/2026-01-07-ebpf-tracing-bpftrace-bcc/view](https://oneuptime.com/blog/post/2026-01-07-ebpf-tracing-bpftrace-bcc/view)  
44. Probes \- Building eBPF Programs with Aya, accessed on May 11, 2026, [https://aya-rs.dev/book/programs/probes.html](https://aya-rs.dev/book/programs/probes.html)  
45. Mastering pg\_stat\_activity for real-time monitoring in PostgreSQL® \- Instaclustr, accessed on May 11, 2026, [https://www.instaclustr.com/blog/mastering-pg-stat-activity-for-real-time-monitoring-in-postgresql/](https://www.instaclustr.com/blog/mastering-pg-stat-activity-for-real-time-monitoring-in-postgresql/)  
46. Is there a way to get pg\_stat\_activity information without using an SQL connection?, accessed on May 11, 2026, [https://stackoverflow.com/questions/59317434/is-there-a-way-to-get-pg-stat-activity-information-without-using-an-sql-connecti](https://stackoverflow.com/questions/59317434/is-there-a-way-to-get-pg-stat-activity-information-without-using-an-sql-connecti)  
47. Diagnose Active SQL Queries with pg\_stat\_activity \- AnalyticDB for PostgreSQL \- Alibaba Cloud, accessed on May 11, 2026, [https://www.alibabacloud.com/help/en/analyticdb/analyticdb-for-postgresql/use-cases/use-pg-stat-activity-to-analyze-and-diagnose-active-sql-queries](https://www.alibabacloud.com/help/en/analyticdb/analyticdb-for-postgresql/use-cases/use-pg-stat-activity-to-analyze-and-diagnose-active-sql-queries)  
48. How to troubleshoot Postgres performance using FlameGraphs and eBPF (or perf), accessed on May 11, 2026, [https://postgres.ai/docs/postgres-howtos/monitoring-troubleshooting/system-monitoring/flamegraphs-for-postgres](https://postgres.ai/docs/postgres-howtos/monitoring-troubleshooting/system-monitoring/flamegraphs-for-postgres)  
49. debugging \- How to use pg\_stat\_activity? \- Stack Overflow, accessed on May 11, 2026, [https://stackoverflow.com/questions/17654033/how-to-use-pg-stat-activity](https://stackoverflow.com/questions/17654033/how-to-use-pg-stat-activity)  
50. Postgres Log Monitoring 101: Deadlocks, Checkpoint Tuning & Blocked Queries · pganalyze, accessed on May 11, 2026, [https://pganalyze.com/blog/postgresql-log-monitoring-101-deadlocks-checkpoints-blocked-queries](https://pganalyze.com/blog/postgresql-log-monitoring-101-deadlocks-checkpoints-blocked-queries)  
51. GitHub \- aya-rs/aya: Aya is an eBPF library for the Rust programming language, built with a focus on developer experience and operability., accessed on May 11, 2026, [https://github.com/aya-rs/aya](https://github.com/aya-rs/aya)  
52. Linnix: eBPF observability in pure Rust (using Aya) \- Reddit, accessed on May 11, 2026, [https://www.reddit.com/r/rust/comments/1oslvui/linnix\_ebpf\_observability\_in\_pure\_rust\_using\_aya/](https://www.reddit.com/r/rust/comments/1oslvui/linnix_ebpf_observability_in_pure_rust_using_aya/)  
53. Getting Started \- Building eBPF Programs with Aya, accessed on May 11, 2026, [https://aya-rs.dev/book/](https://aya-rs.dev/book/)  
54. How to write an eBPF/XDP load-balancer in Rust | Kong Inc., accessed on May 11, 2026, [https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust](https://konghq.com/blog/engineering/writing-an-ebpf-xdp-load-balancer-in-rust)  
55. Using aya-tool \- Building eBPF Programs with Aya \- aya-rs.dev, accessed on May 11, 2026, [https://aya-rs.dev/book/aya/aya-tool](https://aya-rs.dev/book/aya/aya-tool)  
56. Enhancing your Aya program with eBPF maps \- DEV Community, accessed on May 11, 2026, [https://dev.to/littlejo/enhancing-your-aya-program-with-ebpf-maps-4hdj](https://dev.to/littlejo/enhancing-your-aya-program-with-ebpf-maps-4hdj)  
57. Aya Rust Tutorial part 5: Using Maps | by steve latif \- Medium, accessed on May 11, 2026, [https://medium.com/@stevelatif/aya-rust-tutorial-part-5-using-maps-4d26c4a2fff8](https://medium.com/@stevelatif/aya-rust-tutorial-part-5-using-maps-4d26c4a2fff8)  
58. usdt \- Rust \- Docs.rs, accessed on May 11, 2026, [https://docs.rs/usdt/](https://docs.rs/usdt/)