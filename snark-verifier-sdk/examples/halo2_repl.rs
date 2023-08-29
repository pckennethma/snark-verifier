use std::fs::File;
use std::io::{BufReader, Read};

use halo2_base::gates::builder::{
    BaseConfigParams, CircuitBuilderStage, RangeWithInstanceCircuitBuilder,
};
use halo2_base::gates::flex_gate::GateStrategy;
use halo2_base::halo2_proofs;
use halo2_base::halo2_proofs::arithmetic::Field;
use halo2_base::halo2_proofs::halo2curves::bn256::{Fr, G1Affine, Bn256};
use halo2_base::halo2_proofs::plonk::{VerifyingKey, verify_proof};
use halo2_base::halo2_proofs::poly::commitment::{Params, ParamsProver};
use halo2_base::halo2_proofs::poly::kzg::commitment::KZGCommitmentScheme;
use halo2_base::halo2_proofs::poly::kzg::multiopen::VerifierSHPLONK;
use halo2_base::halo2_proofs::poly::kzg::strategy::SingleStrategy;
use halo2_base::utils::fs::gen_srs;
use halo2_proofs::halo2curves as halo2_curves;

use rand::rngs::StdRng;
use rand::SeedableRng;
use snark_verifier::util::arithmetic::PrimeField;
// use snark_verifier_sdk::halo2::aggregation::{AggregationConfigParams, VerifierUniversality};
use snark_verifier_sdk::{SHPLONK, NativeLoader};
use snark_verifier_sdk::halo2::PoseidonTranscript;
use snark_verifier_sdk::{
    gen_pk,
    halo2::{aggregation::AggregationCircuit, gen_snark_shplonk},
    Snark,
};

fn read_halo2_repl_snark(path: &str) -> Snark {
    let mut file = File::open(path).expect("File open error");

    let mut raw_snark = Vec::new();
    file.read_to_end(&mut raw_snark).expect("File read error");

    let snark: Snark = bincode::deserialize(&raw_snark).expect("Snark deserialize error");
    let omega_bytes: [u8; 32] = [
        172, 60, 171, 234, 230, 219, 25, 145, 160, 115, 93, 51, 202, 217, 38, 214, 7, 12, 154, 158,
        132, 18, 162, 42, 43, 191, 64, 159, 209, 172, 55, 35,
    ];
    let omega = Fr::from_repr(omega_bytes).unwrap();
    assert_eq!(snark.protocol.domain.gen, omega);
    assert_eq!(snark.protocol.domain.k, 14);
    // dbg!(snark.protocol.domain.gen);
    snark
}

fn read_vk(path: &str) -> VerifyingKey<G1Affine> {
    let mut file = File::open(path).expect("File open error");
    let mut raw_vk = Vec::new();
    file.read_to_end(&mut raw_vk).expect("File read error");

    let vk_reader = &mut BufReader::new(raw_vk.as_slice());
    let params = BaseConfigParams {
        strategy: GateStrategy::Vertical,
        num_advice_per_phase: vec![4, 0, 0],
        num_lookup_advice_per_phase: vec![1, 0, 0],
        num_fixed: 1,
        k: 14,
        lookup_bits: Some(8),
    };
    let vk =
        VerifyingKey::<G1Affine>::read::<BufReader<&[u8]>, RangeWithInstanceCircuitBuilder<Fr>>(
            vk_reader,
            halo2_base::halo2_proofs::SerdeFormat::RawBytesUnchecked,
            params,
        )
        .expect("VerifyingKey read error");
    vk
}

fn main() {
    let k = 14;
    let snark = read_halo2_repl_snark("./halo2repl.snark");
    let vk = read_vk("./halo2repl.vk");

    let params = gen_srs(k);

    let verifier_params = params.verifier_params();
    let strategy = SingleStrategy::new(&params);
    let mut transcript = PoseidonTranscript::<NativeLoader, &[u8]>::new::<0>(&snark.proof[..]);
    let instance = &snark.instances[0][..];
    verify_proof::<
        KZGCommitmentScheme<Bn256>,
        VerifierSHPLONK<'_, Bn256>,
        _,
        _,
        SingleStrategy<'_, Bn256>,
    >(verifier_params, &vk, strategy, &[&[instance]], &mut transcript)
    .unwrap();
}
