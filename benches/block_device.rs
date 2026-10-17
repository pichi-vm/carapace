// SPDX-FileCopyrightText: Advanced Micro Devices, Inc.
// SPDX-License-Identifier: Apache-2.0

mod support;

use carapace::{Assemble, Chain, FromGpt};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, SamplingMode};
use devmap_linux::Control;
use std::{
    hint::black_box,
    time::{Duration, Instant},
};
use support::{wait_empty, Fixture};

fn benchmark(criterion: &mut Criterion) {
    let control = Control::open().expect("benchmarks require root and device-mapper access");
    for target in ["zero", "snapshot", "verity"] {
        control
            .version(target)
            .expect("required device-mapper target unavailable");
    }
    for depth in [1, 2, 4, 8, 16, 32] {
        let fixture =
            Fixture::new(&control, depth).expect("block-device fixture setup/validation failed");
        let mut group = criterion.benchmark_group("block_device");
        group
            .sample_size(10)
            .sampling_mode(SamplingMode::Flat)
            .warm_up_time(Duration::from_secs(1))
            .measurement_time(Duration::from_secs(3));
        group.bench_function(BenchmarkId::new("discovery", depth), |bencher| {
            bencher.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    let start = Instant::now();
                    let chain =
                        Chain::from_gpt(black_box(&fixture.root)).expect("discovery failed");
                    elapsed += start.elapsed();
                    black_box(&chain);
                    drop(chain);
                }
                elapsed
            });
        });
        group.bench_function(BenchmarkId::new("fresh_activation", depth), |bencher| {
            bencher.iter_custom(|iterations| {
                let mut elapsed = Duration::ZERO;
                for _ in 0..iterations {
                    wait_empty(&control).expect("previous activation still alive");
                    let chain = Chain::from_gpt(&fixture.root).expect("discovery failed");
                    let start = Instant::now();
                    let file = black_box(&chain).assemble().expect("activation failed");
                    elapsed += start.elapsed();
                    black_box(&file);
                    drop(file);
                    drop(chain);
                    wait_empty(&control).expect("activation cleanup failed");
                }
                elapsed
            });
        });
        group.finish();
    }
}
criterion_group!(benches, benchmark);
criterion_main!(benches);
