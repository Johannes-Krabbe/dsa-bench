use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::seq::SliceRandom;
use signature::*;
use slh_dsa::*;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("slh_dsa_128s");
    group.sample_size(100);
    group.sampling_mode(criterion::SamplingMode::Flat);
    group.measurement_time(std::time::Duration::new(120, 0));

    let mut rng = rand::thread_rng();

    let mut message = [0u8; 128];
    for i in 0..message.len() {
        message[i] = (i % 256) as u8;
    }
    message.shuffle(&mut rng);

    let sk = SigningKey::<Shake128s>::new(&mut rng);
    let sig = sk.try_sign(&message).unwrap();
    let vk = sk.verifying_key();

    // Key generation
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let key = slh_dsa::SigningKey::<Shake128s>::new(&mut rng);
            black_box(key);
        })
    });

    // Signing
    group.bench_function("sign", |b| {
        b.iter(|| {
            let sig = sk.try_sign(&message).unwrap();
            black_box(sig)
        })
    });

    // Verifying
    group.bench_function("verify", |b| {
        b.iter(|| {
            let ok = vk.verify(&message, &sig);
            black_box(ok)
        })
    });

    // Round trip
    group.bench_function("round_trip", |b| {
        b.iter(|| {
            let key = slh_dsa::SigningKey::<Shake128s>::new(&mut rng);
            let sig = key.try_sign(&message).unwrap();
            let vk = key.verifying_key();
            let ok = vk.verify(&message, &sig);
            let _ = black_box(ok);
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
