use criterion::{criterion_group, criterion_main, Criterion};
use hybrid_array::{Array, ArraySize};
use ml_dsa::{KeyGen, MlDsa65, B32};
use rand::CryptoRng;

pub fn rand<L: ArraySize, R: CryptoRng + ?Sized>(rng: &mut R) -> Array<u8, L> {
    let mut val = Array::<u8, L>::default();
    rng.fill_bytes(&mut val);
    val
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa");
    group.sample_size(1000);
    group.sampling_mode(criterion::SamplingMode::Flat);

    let mut rng = rand::rng();
    let xi: B32 = rand(&mut rng);
    let m: B32 = rand(&mut rng);
    let ctx: B32 = rand(&mut rng);

    // Create initial objects for reuse in benchmarks
    let kp = MlDsa65::key_gen_internal(&xi);
    let sk = kp.signing_key();
    let vk = kp.verifying_key();
    let sig = sk.sign_deterministic(&m, &ctx).unwrap();

    // Key generation (without serialization)
    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _kp = MlDsa65::key_gen_internal(&xi);
        })
    });

    // Signing (without serialization)
    group.bench_function("sign", |b| {
        b.iter(|| {
            let _sig = sk.sign_deterministic(&m, &ctx);
        })
    });

    // Verifying (without serialization)
    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ver = vk.verify_with_context(&m, &ctx, &sig);
        })
    });

    // Round trip
    group.bench_function("round_trip", |b| {
        b.iter(|| {
            let kp = MlDsa65::key_gen_internal(&xi);
            let sig = kp.signing_key().sign_deterministic(&m, &ctx).unwrap();
            let _ver = kp.verifying_key().verify_with_context(&m, &ctx, &sig);
        })
    });

    // Combined operations (explicit steps)
    group.bench_function("combined_explicit_steps", |b| {
        b.iter(|| {
            let kp = MlDsa65::key_gen_internal(&xi);
            let sk = kp.signing_key();
            let vk = kp.verifying_key();
            let sig = sk.sign_deterministic(&m, &ctx).unwrap();
            let _ver = vk.verify_with_context(&m, &ctx, &sig);
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
