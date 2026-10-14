# Bootstrap policy latency

The native verifier sends 500 sequential Evaluate calls (one pure diagnostic)
and 500 Check calls (two checks, allow plus unconditional floor deny) through
the real MemoryBus broker and dynamically loaded native module. Each sample
uses exactly one bus call. This is a synthetic check batch, not a measured
product conversation; calls per representative turn still need measurement.

Measured on Linux 7.0.0-31-generic x86_64, Rust 1.99.0 (b940084d7), debug build,
October 10, 2026:

| Native method | p50 | p99 |
| --- | --- | --- |
| Evaluate | 486 us | 4.336 ms |
| Check (two checks) | 537 us | 4.442 ms |

A repeat after contention subsided measured Evaluate 189 us p50 / 385 us p99
and Check 210 us p50 / 395 us p99, showing why the final release gate must use
a controlled runner and representative workload.

The characterized host debug path over two checks was 35 us p50 / 63 us p99.
The native boundary is substantially slower in this debug workload. These
numbers do not establish release-build performance, or a product migration
budget. A provisional gate to measure before migration is <=1 ms p50 and
<=10 ms p99 per batched Check on the same supported native runner. That gate
must be agreed against a representative released-module workload and its
number of calls per turn before host callers move. Bootstrap remains
release-gated irrespective of this synthetic result.

## Release budget (enforced in CI)

Release build, same workload (500 samples per method, Linux x86_64, October 14,
2026): Evaluate 50.6 us p50 / 62.9 us p99; Check (two checks) 52.1 us p50 /
68.6 us p99.

The agreed budget per bus call on a supported native runner is p50 <= 1 ms and
p99 <= 10 ms for both Evaluate and Check, roughly 20x and 150x headroom over
the measured release numbers so noisy hosted runners do not flake. The CI `perf`
job builds in release mode and runs the verifier with
`TINYSECURITY_PERF_BUDGET=1`, which fails the run when either method exceeds
the budget (and refuses to run on a debug build). Tighten the constants in
`verify_module.rs` if a dedicated controlled runner is added.

Reproduce with:

```sh
cargo build --all-targets --all-features
cargo run -p tinysecurity-module --example verify_module -- target/debug/libtinysecurity_module.so
```

Budget check: `TINYSECURITY_PERF_BUDGET=1 cargo run --release -p tinysecurity-module --example verify_module -- target/release/libtinysecurity_module.so`.

Use the platform library extension on macOS/Windows. Archive timing can be run
with release URL, archive name and published digest as the three arguments.
