use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::{rngs::OsRng, seq::SliceRandom};

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519");
    group.sample_size(100);
    group.sampling_mode(criterion::SamplingMode::Flat);
    group.measurement_time(std::time::Duration::new(30, 0));

    let mut message = [0u8; 128];
    for i in 0..message.len() {
        message[i] = (i % 256) as u8;
    }
    message.shuffle(&mut OsRng);

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let signing_key = SigningKey::generate(&mut OsRng);
            black_box(signing_key);
        })
    });

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature: Signature = signing_key.sign(&message);
            black_box(signature);
        })
    });

    let signature: Signature = signing_key.sign(&message);

    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = verifying_key.verify(&message, &signature);
            let _ = black_box(result);
        })
    });

    group.bench_function("round_trip", |b| {
        b.iter(|| {
            let signing_key = SigningKey::generate(&mut OsRng);
            let verifying_key = VerifyingKey::from(&signing_key);

            let signature: Signature = signing_key.sign(&message);

            let result = verifying_key.verify(&message, &signature);
            let _ = black_box(result);
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
