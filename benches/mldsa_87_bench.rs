use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hybrid_array::{Array, ArraySize};
use ml_dsa::{KeyGen, MlDsa87, B32};
use rand::{seq::SliceRandom, CryptoRng};

pub fn generate_random_bytes<L: ArraySize, R: CryptoRng + ?Sized>(rng: &mut R) -> Array<u8, L> {
    let mut random_bytes = Array::<u8, L>::default();
    rng.fill_bytes(&mut random_bytes);
    random_bytes
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("ml_dsa_87");

    group.sample_size(100);
    group.sampling_mode(criterion::SamplingMode::Flat);
    group.measurement_time(std::time::Duration::new(30, 0));

    let mut crypto_rng = rand::rng();

    let seed: B32 = generate_random_bytes(&mut crypto_rng);
    let signing_context: B32 = generate_random_bytes(&mut crypto_rng);

    let mut message = [0u8; 128];
    for i in 0..message.len() {
        message[i] = (i % 256) as u8;
    }
    message.shuffle(&mut crypto_rng);

    let key_pair = MlDsa87::key_gen_internal(&seed);
    let signing_key = key_pair.signing_key();
    let verification_key = key_pair.verifying_key();
    let signature = signing_key
        .sign_deterministic(&message, &signing_context)
        .unwrap();

    group.bench_function("keygen", |b| {
        b.iter(|| {
            let _kp = MlDsa87::key_gen_internal(&seed);
            black_box(_kp);
        })
    });

    group.bench_function("sign", |b| {
        b.iter(|| {
            let _sig = signing_key.sign_deterministic(&message, &signing_context);
            let _ = black_box(_sig);
        })
    });

    group.bench_function("verify", |b| {
        b.iter(|| {
            let _ver = verification_key.verify_with_context(&message, &signing_context, &signature);
            black_box(_ver);
        })
    });

    group.bench_function("round_trip", |b| {
        b.iter(|| {
            let kp = MlDsa87::key_gen_internal(&seed);
            let sig = kp
                .signing_key()
                .sign_deterministic(&message, &signing_context)
                .unwrap();
            let _ver = kp
                .verifying_key()
                .verify_with_context(&message, &signing_context, &sig);
            black_box(_ver);
            black_box(sig);
            black_box(kp);
        })
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
