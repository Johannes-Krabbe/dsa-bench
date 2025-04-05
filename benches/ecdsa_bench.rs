use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
use p256::NistP256;
use rand_core::OsRng;

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ecdsa");
    group.sample_size(1000);
    group.sampling_mode(criterion::SamplingMode::Flat);

    // Test message to sign
    let message = b"ECDSA benchmarking message";

    // Key generation (without serialization)
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let signing_key = black_box(SigningKey::<NistP256>::random(&mut OsRng));
            black_box(signing_key);
        })
    });

    // Create a key outside the benchmark for signing/verification tests
    let signing_key = SigningKey::<NistP256>::random(&mut OsRng);
    let verifying_key = VerifyingKey::from(&signing_key);

    // Signing (without serialization)
    group.bench_function("sign", |b| {
        b.iter(|| {
            let signature: Signature<NistP256> = black_box(signing_key.sign(black_box(message)));
            black_box(signature);
        })
    });

    // Create a signature outside the benchmark for verification test
    let signature: Signature<NistP256> = signing_key.sign(message);

    // Verifying (without serialization)
    group.bench_function("verify", |b| {
        b.iter(|| {
            let result = black_box(verifying_key.verify(black_box(message), &black_box(signature)));
            let _ = black_box(result);
        })
    });

    // Round trip
    group.bench_function("round_trip", |b| {
        b.iter(|| {
            // Generate key
            let signing_key = black_box(SigningKey::<NistP256>::random(&mut OsRng));
            let verifying_key = black_box(VerifyingKey::from(&signing_key));

            // Sign message
            let signature: Signature<NistP256> = black_box(signing_key.sign(black_box(message)));

            // Verify signature
            let result = black_box(verifying_key.verify(black_box(message), &black_box(signature)));
            let _ = black_box(result);
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
