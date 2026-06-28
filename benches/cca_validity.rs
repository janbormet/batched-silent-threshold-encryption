use ark_std::test_rng;
use criterion::{criterion_group, criterion_main, Criterion};
use silent_batched_threshold_encryption::{
    bte::{self, encryption::NUM_CHUNKS},
    cca::{CcaStatementContext, PedersenCommitments, RangeProof, SchnorrProof, ValidityProof},
    ste,
};

type E = ark_bls12_381::Bls12_381;

fn bench_cca_validity(c: &mut Criterion) {
    let mut rng = test_rng();
    let n = 64;
    let l = NUM_CHUNKS;
    let batch_size = 512;
    let t: usize = n / 2;
    let position = 0;

    let bte_crs = bte::crs::CRS::<E>::new(batch_size, &mut rng);
    let ste_crs = ste::crs::CRS::new(n, l, &mut rng);

    let sk = (0..n)
        .map(|i| ste::setup::SecretKey::<E>::new(&mut rng, i))
        .collect::<Vec<_>>();
    let pk = sk
        .iter()
        .enumerate()
        .map(|(i, sk)| sk.get_lagrange_pk(i, &ste_crs))
        .collect::<Vec<_>>();
    let (_ak, ek) = ste::aggregate::AggregateKey::<E>::new(pk, &ste_crs);
    let context = CcaStatementContext::new(&bte_crs, &ste_crs, &ek);

    let (ciphertext, witness) =
        bte::encryption::encrypt_with_witness(position, &bte_crs, &ste_crs, &ek, t, &mut rng);
    let (commitments, openings) = PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
    let proof = ValidityProof::prove_with_context(
        &context,
        &ciphertext,
        &bte_crs,
        &ste_crs,
        &ek,
        &commitments,
        &witness,
        &openings,
        &mut rng,
    );
    let range_proof = RangeProof::prove_with_context(
        &context.range_params_digest,
        &commitments,
        &witness,
        &openings,
        &ste_crs,
        &mut rng,
    );
    let schnorr_proof = SchnorrProof::prove_with_context(
        &context,
        &ciphertext,
        &bte_crs,
        &ste_crs,
        &ek,
        &commitments,
        &witness,
        &openings,
        &mut rng,
    );

    let mut group = c.benchmark_group("cca_validity");

    group.bench_function("encryption_only", |b| {
        b.iter(|| bte::encryption::encrypt(position, &bte_crs, &ste_crs, &ek, t, &mut rng))
    });

    group.bench_function("pedersen_commitments_only", |b| {
        b.iter(|| PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng))
    });

    group.bench_function("range_prove_only", |b| {
        b.iter(|| {
            RangeProof::prove_with_context(
                &context.range_params_digest,
                &commitments,
                &witness,
                &openings,
                &ste_crs,
                &mut rng,
            )
        })
    });

    group.bench_function("range_verify_only", |b| {
        b.iter(|| {
            range_proof.verify_with_context(&context.range_params_digest, &commitments, &ste_crs)
        })
    });

    group.bench_function("schnorr_prove_after_encryption", |b| {
        b.iter(|| {
            SchnorrProof::prove_with_context(
                &context,
                &ciphertext,
                &bte_crs,
                &ste_crs,
                &ek,
                &commitments,
                &witness,
                &openings,
                &mut rng,
            )
        })
    });

    group.bench_function("schnorr_verify", |b| {
        b.iter(|| {
            schnorr_proof.verify_with_context(
                &context,
                &ciphertext,
                &bte_crs,
                &ste_crs,
                &ek,
                &commitments,
            )
        })
    });

    group.bench_function("validity_prove_after_encryption", |b| {
        b.iter(|| {
            ValidityProof::prove_with_context(
                &context,
                &ciphertext,
                &bte_crs,
                &ste_crs,
                &ek,
                &commitments,
                &witness,
                &openings,
                &mut rng,
            )
        })
    });

    group.bench_function("validity_verify", |b| {
        b.iter(|| {
            proof.verify_with_context(&context, &ciphertext, &bte_crs, &ste_crs, &ek, &commitments)
        })
    });

    group.bench_function("commitments_plus_validity_prove_after_encryption", |b| {
        b.iter(|| {
            let (commitments, openings) =
                PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
            ValidityProof::prove_with_context(
                &context,
                &ciphertext,
                &bte_crs,
                &ste_crs,
                &ek,
                &commitments,
                &witness,
                &openings,
                &mut rng,
            )
        })
    });

    group.bench_function("encryption_plus_commitments_plus_validity_prove", |b| {
        b.iter(|| {
            let (ciphertext, witness) = bte::encryption::encrypt_with_witness(
                position, &bte_crs, &ste_crs, &ek, t, &mut rng,
            );
            let (commitments, openings) =
                PedersenCommitments::commit(&witness.chunks, &ste_crs, &mut rng);
            (
                ciphertext.clone(),
                commitments.clone(),
                ValidityProof::prove_with_context(
                    &context,
                    &ciphertext,
                    &bte_crs,
                    &ste_crs,
                    &ek,
                    &commitments,
                    &witness,
                    &openings,
                    &mut rng,
                ),
            )
        })
    });

    group.finish();
}

criterion_group!(benches, bench_cca_validity);
criterion_main!(benches);
