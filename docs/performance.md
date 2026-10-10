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

Reproduce with:

```sh
cargo build --all-targets --all-features
cargo run -p tinysecurity-module --example verify_module -- target/debug/libtinysecurity_module.so
```

Use the platform library extension on macOS/Windows. Archive timing can be run
with release URL, archive name and published digest as the three arguments.
