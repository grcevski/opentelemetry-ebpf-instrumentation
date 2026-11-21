# Rust runtime instrumentation

OBI tracks spawned Tokio tasks on Linux amd64 and arm64 with stable rustc
1.97.x through 1.100.x. OBI reads the compiler version from the executable.
If the version string is absent, OBI can identify the compiler from a known
standard-library commit. The executable must retain the Tokio function symbols
used for poll and task creation or deallocation. Debug information is optional.

A worker can switch between unrelated tasks. OBI follows the task across polls
and copies its parent when it spawns another task. It checks alternative hooks
for optimized builds and keeps generic capture available when hooks are missing.
Threads that never poll a Tokio task, such as `std::thread` or rayon workers,
keep per-thread request tracking. A task spawned from such a thread inherits the
request that thread is serving.

## Hyper and reqwest

Hyper can write a request on a different task from its caller. OBI follows its
request queues and uses the active request to correlate the client span and
outgoing HTTP/1 header. For cleartext connections the socket injector uses the
same ownership information when user-memory writes are unavailable.

OBI selects HTTP/1 field offsets using the architecture, exact rustc patch,
and crate versions recorded in its database. Tokio task tracking still works
on supported patches without measured offsets. The offset generator reads
debug information from fixture builds. Instrumented applications only need
retained symbols.
Run `make update-offsets` to update the database.

## Log enrichment

When log enrichment is enabled for a Rust service, OBI can add the current
task’s trace and span IDs to logs written to stdout or stderr. A task can yield
and resume on another worker and still log with the same context. OBI looks up
the context when the write occurs, so a logger that queues records for a
dedicated writer thread loses the originating task’s context.
See [trace-log correlation](trace-log-correlation.md#rust-tokio-task-polls).
