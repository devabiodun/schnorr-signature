use ark_bls12_381::{Fr as ScalarField, G1Affine, G1Projective};
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, Fp, MontBackend, MontConfig, UniformRand};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};
use std::ops::Mul;

pub struct SchnorrSig {}

// consider the base field of the BLS12_381 curve:
// Since the base field has 381 bits, we use u64 array of of size 6 that can accommodate for 384 bits.
#[derive(MontConfig)]
#[modulus = "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787"]
#[generator = "2"]
pub struct FqConfig;
pub type Fq = Fp<MontBackend<FqConfig, 6>, 6>;

impl SchnorrSig {
    fn generate_keypair() -> (ScalarField, G1Affine) {
        // private key
        let private_key: ScalarField = ScalarField::rand(&mut rand::thread_rng());
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

    fn sign(private_key: ScalarField, message: &[u8]) -> (G1Affine, ScalarField) {
        // Generate a random nonce alpha_t from Zq
        let alpha_t: ScalarField = ScalarField::rand(&mut rand::thread_rng());

        // Compute u_t = g^alpha_t
        let u_t = G1Projective::generator() * alpha_t;
        let u_t_affine: G1Affine = u_t.into_affine();

        // Hash message and u_t to get c
        let c = SchnorrSig::hash_message_and_ut(message, &u_t_affine);

        // Compute alpha_z = alpha_t + alpha_c
        let alpha_z = alpha_t + (private_key * c);

        (u_t_affine, alpha_z)
    }

    fn hash_message_and_ut(message: &[u8], u_t: &G1Affine) -> ScalarField {
        let mut u_t_serialized_bytes = Vec::new();

        u_t.serialize_compressed(&mut u_t_serialized_bytes)
            .expect("Serialization failed");

        let mut hasher = Sha256::new();
        hasher.update(message);
        hasher.update(&u_t_serialized_bytes);
        let hash_result = hasher.finalize();

        ScalarField::from_random_bytes(&hash_result)
            .unwrap_or(ScalarField::rand(&mut rand::thread_rng()))
    }

    pub fn verify(
        public_key: G1Affine,
        message: &[u8],
        signature: (G1Affine, ScalarField),
    ) -> bool {
        let (u_t, alpha_z) = signature;

        // compute c = H(m, u_t)
        let c = SchnorrSig::hash_message_and_ut(message, &u_t);

        // compute g = u_t * u^c
        let g = G1Projective::generator() * alpha_z;

        let u_c = &public_key.mul(ScalarField::from(c));

        let g_prime = u_t + u_c;

        // check: g = u_t * u^c
        g == g_prime
    }
}

pub fn main() {
    let (sk, pk) = SchnorrSig::generate_keypair();

    let msg = b"Hello world!";

    let sig = SchnorrSig::sign(sk, msg);
    let verify = SchnorrSig::verify(pk, msg, sig);
    println!("Verify={}", verify);
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let (sk, pk) = SchnorrSig::generate_keypair();
        let msg = b"Hello world!";

        let sig = SchnorrSig::sign(sk, msg);
        let verify = SchnorrSig::verify(pk, msg, sig);

        assert_eq!(verify, true);
    }

    #[test]
    fn test_sign_verify_tampered_message() {
        let (sk, pk) = SchnorrSig::generate_keypair();

        let msg = b"Hello world!";
        let tampered_msg = b"Hello world!!";

        let sig = SchnorrSig::sign(sk, msg);
        let verify = SchnorrSig::verify(pk, tampered_msg, sig);

        assert_eq!(verify, false);
    }

    #[test]
    fn test_sign_verify_tampered_signature() {
        let (sk, pk) = SchnorrSig::generate_keypair();

        let msg = b"Hello world!";

        let (ut, _) = SchnorrSig::sign(sk, msg);
        let verify = SchnorrSig::verify(pk, msg, (ut, ScalarField::rand(&mut rand::thread_rng())));

        assert_eq!(verify, false);
    }

    #[test]
    fn test_sign_verify_tampered_secret_key() {
        let (_, pk) = SchnorrSig::generate_keypair();
        let (tampered_sk, _) = SchnorrSig::generate_keypair();

        let msg = b"Hello world!";

        let tampered_sig = SchnorrSig::sign(tampered_sk, msg);
        let tampered_verify = SchnorrSig::verify(pk, msg, tampered_sig);

        assert_eq!(tampered_verify, false);
    }
}
