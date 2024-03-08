use ark_bls12_381::{Fr, FrConfig, G1Affine, G1Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::UniformRand;
use ark_ff::{
    // field_hashers::{DefaultFieldHasher, HashToField},
    fields::{Fp, Fp64, MontBackend, MontConfig},
};
pub struct SchnorrSig {}

// consider the base field of the BLS12_381 curve:
// Since the base field has 381 bits, we use u64 array of of size 6 that can accommodate for 384 bits.
#[derive(MontConfig)]
#[modulus = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"]
#[generator = "2"]
pub struct FqConfig;
pub type Fq = Fp<MontBackend<FqConfig, 6>, 6>;

impl SchnorrSig {
    fn generate_keypair() -> (
        Fr,
        ark_ec::short_weierstrass::Affine<ark_bls12_381::g1::Config>,
    ) {
        // private key
        let private_key: Fr = Fr::rand(&mut rand::thread_rng());
        // public key
        let public_key = G1Projective::generator() * private_key;
        // public key in projective coordinates
        let public_key_projective = G1Projective::new(
            public_key.x.into(),
            public_key.y.into(),
            public_key.z.into(),
        );
        // convert to affine coordinates
        let public_key_affine: G1Affine = public_key_projective.into_affine();
        
        (private_key, public_key_affine)
    }
}

pub fn main() {
    let (sk, pk) = SchnorrSig::generate_keypair();
    println!("Private Key={:?}, Public Key={:?}", sk, pk);
}
