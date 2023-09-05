use std::fs::File;
use std::io::{BufReader, Read};

use halo2_base::gates::circuit::builder::BaseCircuitBuilder;
use halo2_base::gates::circuit::BaseCircuitParams;
use halo2_base::gates::{GateChip, GateInstructions, RangeInstructions};

use halo2_base::halo2_proofs::halo2curves::bn256::{Bn256, Fr, G1Affine};
use halo2_base::halo2_proofs::plonk::{verify_proof, VerifyingKey};
use halo2_base::halo2_proofs::poly::commitment::ParamsProver;
use halo2_base::halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::{AccumulatorStrategy, SingleStrategy};
use halo2_base::utils::fs::gen_srs;

use itertools::Itertools;
use snark_verifier_sdk::halo2::POSEIDON_SPEC;
use snark_verifier_sdk::halo2::{gen_snark_shplonk, PoseidonTranscript};
use snark_verifier_sdk::Snark;
use snark_verifier_sdk::{gen_pk, NativeLoader};

fn generate_circuit() {
    let lookup_bits = 8;
    let circuit_params = BaseCircuitParams {
        k: 14 as usize,
        num_advice_per_phase: vec![4, 0, 0],
        num_lookup_advice_per_phase: vec![1, 0, 0],
        num_fixed: 1,
        lookup_bits: Some(lookup_bits),
        num_instance_columns: 1,
    };
    let mut builder = BaseCircuitBuilder::new(false).use_params(circuit_params);
    let gate = GateChip::default();

    let ctx = builder.main(0);

    let x = ctx.load_constant(Fr::from(1));
    let y = ctx.load_constant(Fr::from(2));
    let z = gate.add(ctx, x, y);

    let params = gen_srs(14);
    let pk = gen_pk(&params, &builder, None);
    let vk = pk.get_vk();


    // Uncommenting this will result in proof verification failure
    //
    // let file = vk.to_bytes(halo2_base::halo2_proofs::SerdeFormat::RawBytesUnchecked);
    // let circuit_params = BaseCircuitParams {
    //     k: 14,
    //     num_advice_per_phase: vec![1, 0, 0],
    //     num_fixed: 1,
    //     num_lookup_advice_per_phase: vec![1, 0, 0],
    //     num_instance_columns: 1,
    //     lookup_bits: Some(8),
    // };
    // let vk = VerifyingKey::<G1Affine>::from_bytes::<BaseCircuitBuilder<Fr>>(
    //     &file,
    //     halo2_base::halo2_proofs::SerdeFormat::RawBytesUnchecked,
    //     circuit_params,
    // )
    // .expect("VerifyingKey read error");

    let snark = gen_snark_shplonk(&params, &pk, builder, None::<&str>);

    let verifier_params = params.verifier_params();
    let mut transcript_read =
        PoseidonTranscript::<NativeLoader, &[u8]>::from_spec(&snark.proof, POSEIDON_SPEC.clone());

    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        _,
        _,
        AccumulatorStrategy<'_, Bn256>,
    >(
        verifier_params,
        &vk,
        AccumulatorStrategy::new(params.verifier_params()),
        &[&[&[]]],
        &mut transcript_read,
    )
    .unwrap();
}

fn main() {
    generate_circuit();
}
