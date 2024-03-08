use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::fields::{Fp, MontBackend, MontConfig};
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

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

    fn sign(private_key: Fr, message: &[u8]) -> (G1Affine, Fr) {
        // Generate a random nonce alpha_t from Zq
        let alpha_t: Fr = Fr::rand(&mut rand::thread_rng());

        // Compute u_t = g^alpha_t
        let u_t = G1Projective::generator() * alpha_t;
        let u_t_affine: G1Affine = u_t.into_affine();

        // Hash message and u_t to get c
        let c = SchnorrSig::hash_message_and_ut(message, &u_t_affine);

        // Compute alpha_z = alpha_t + alpha_c
        let alpha_z = alpha_t + (private_key * c);

        (u_t_affine, alpha_z)
    }

    fn hash_message_and_ut(message: &[u8], u_t: &G1Affine) -> Fr {
        // Serialize the coordinates of u_t_affine to bytes
        let mut u_t_serialized_bytes = Vec::new();
    
        u_t.serialize_compressed(&mut u_t_serialized_bytes)
            .expect("Serialization failed");
    
        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&u_t_serialized_bytes);
        let hash_result = hasher.finalize();
    
        // first 32 bytes of hash
        Fr::from_random_bytes(&hash_result[..32]).unwrap()
    }
}


pub fn main() {
    let (sk, pk) = SchnorrSig::generate_keypair();
    // println!("Private Key={:?}, Public Key={:?}", sk, pk);

    let msg = b"Hello world!";

    let (x, y) = SchnorrSig::sign(sk, msg);
    println!(
        "Private Key={:?}, Public Key={:?}, Signature.x={}, Signature.x={}",
        sk, pk, x, y
    );
}
