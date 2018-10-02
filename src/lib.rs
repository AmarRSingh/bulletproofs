#![feature(nll)]
#![feature(external_doc)]
#![feature(try_trait)]
#![deny(missing_docs)]
#![doc(include = "../README.md")]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]

extern crate byteorder;
extern crate core;
extern crate digest;
extern crate rand;
extern crate sha3;

extern crate curve25519_dalek;
extern crate merlin;
extern crate subtle;

#[macro_use]
extern crate serde_derive;
extern crate serde;

#[macro_use]
extern crate failure;

#[cfg(test)]
extern crate bincode;

mod util;

#[doc(include = "../docs/notes.md")]
mod notes {}
mod circuit_proof;
mod errors;
mod generators;
mod inner_product_proof;
mod range_proof;
mod transcript;

pub use errors::ProofError;
pub use generators::{BulletproofGens, BulletproofGensShare, PedersenGens};
pub use range_proof::RangeProof;

#[doc(include = "../docs/aggregation-api.md")]
pub mod rangeproof_mpc {
    pub use errors::MPCError;
    pub use range_proof::dealer;
    pub use range_proof::messages;
    pub use range_proof::party;
}

/// The rank-1 constraint system API for programmatically defining constraint systems.
///
/// # Example
/// ```
/// # extern crate curve25519_dalek;
/// # extern crate bulletproofs;
/// # extern crate merlin;
///
/// use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable, R1CSError};
/// use curve25519_dalek::scalar::Scalar;
///
/// // Make a gadget that adds constraints to a ConstraintSystem, such that the 
/// // y variables are constrained to be a valid shuffle of the x variables.
///
/// struct KShuffleGadget {}
///
/// impl KShuffleGadget {
///     fn fill_cs<CS: ConstraintSystem>(
///         cs: &mut CS,
///         x: Vec<(Variable, Assignment)>,
///         y: Vec<(Variable, Assignment)>,
///     ) -> Result<(), R1CSError> {
///         let one = Scalar::one();
///         let z = cs.challenge_scalar(b"k-shuffle challenge");
///         let neg_z = -z;
/// 
///         if x.len() != y.len() {
///             return Err(R1CSError::InvalidR1CSConstruction);
///         }
///         let k = x.len();
///         if k == 1 {
///             cs.add_constraint([(x[0].0, -one), (y[0].0, one)].iter().collect());
///             return Ok(());
///         }
/// 
///         // Make last x multiplier for i = k-1 and k-2
///         let mut mulx_left = x[k - 1].1 + neg_z;
///         let mut mulx_right = x[k - 2].1 + neg_z;
///         let mut mulx_out = mulx_left * mulx_right;
/// 
///         let mut mulx_out_var_prev = KShuffleGadget::multiplier_helper(
///             cs,
///             neg_z,
///             mulx_left,
///             mulx_right,
///             mulx_out,
///             x[k - 1].0,
///             x[k - 2].0,
///             true,
///         )?;
/// 
///         // Make multipliers for x from i == [0, k-3]
///         for i in (0..k - 2).rev() {
///             mulx_left = mulx_out;
///             mulx_right = x[i].1 + neg_z;
///             mulx_out = mulx_left * mulx_right;
/// 
///             mulx_out_var_prev = KShuffleGadget::multiplier_helper(
///                 cs,
///                 neg_z,
///                 mulx_left,
///                 mulx_right,
///                 mulx_out,
///                 mulx_out_var_prev,
///                 x[i].0,
///                 false,
///             )?;
///         }
/// 
///         // Make last y multiplier for i = k-1 and k-2
///         let mut muly_left = y[k - 1].1 - z;
///         let mut muly_right = y[k - 2].1 - z;
///         let mut muly_out = muly_left * muly_right;
/// 
///         let mut muly_out_var_prev = KShuffleGadget::multiplier_helper(
///             cs,
///             neg_z,
///             muly_left,
///             muly_right,
///             muly_out,
///             y[k - 1].0,
///             y[k - 2].0,
///             true,
///         )?;
/// 
///         // Make multipliers for y from i == [0, k-3]
///         for i in (0..k - 2).rev() {
///             muly_left = muly_out;
///             muly_right = y[i].1 + neg_z;
///             muly_out = muly_left * muly_right;
/// 
///             muly_out_var_prev = KShuffleGadget::multiplier_helper(
///                 cs,
///                 neg_z,
///                 muly_left,
///                 muly_right,
///                 muly_out,
///                 muly_out_var_prev,
///                 y[i].0,
///                 false,
///             )?;
///         }
/// 
///         // Check equality between last x mul output and last y mul output
///         cs.add_constraint(
///             [(muly_out_var_prev, -one), (mulx_out_var_prev, one)]
///                 .iter()
///                 .collect(),
///         );
/// 
///         Ok(())
///     }
/// 
///     fn multiplier_helper<CS: ConstraintSystem>(
///         cs: &mut CS,
///         neg_z: Scalar,
///         left: Assignment,
///         right: Assignment,
///         out: Assignment,
///         left_var: Variable,
///         right_var: Variable,
///         is_last_mul: bool,
///     ) -> Result<Variable, R1CSError> {
///         let one = Scalar::one();
///         let var_one = Variable::One();
/// 
///         // Make multiplier gate variables
///         let (left_mul_var, right_mul_var, out_mul_var) = cs.assign_multiplier(left, right, out)?;
/// 
///         if is_last_mul {
///             // Make last multiplier
///             cs.add_constraint(
///                 [(left_mul_var, -one), (var_one, neg_z), (left_var, one)]
///                     .iter()
///                     .collect(),
///             );
///         } else {
///             // Make intermediate multiplier
///             cs.add_constraint([(left_mul_var, -one), (left_var, one)].iter().collect());
///         }
///         cs.add_constraint(
///             [(right_mul_var, -one), (var_one, neg_z), (right_var, one)]
///                 .iter()
///                 .collect(),
///         );
/// 
///         Ok(out_mul_var)
///     }
/// }
///
/// use bulletproofs::r1cs::{ProverCS, VerifierCS};
/// use bulletproofs::{BulletproofGens, PedersenGens};
/// use merlin::Transcript;
///
/// fn main() {
///     // k=1
///     assert!(shuffle_helper(vec![3], vec![3]).is_ok());
///     assert!(shuffle_helper(vec![6], vec![6]).is_ok());
///     assert!(shuffle_helper(vec![3], vec![6]).is_err());
///     // k=2
///     assert!(shuffle_helper(vec![3, 6], vec![3, 6]).is_ok());
///     assert!(shuffle_helper(vec![3, 6], vec![6, 3]).is_ok());
///     assert!(shuffle_helper(vec![6, 6], vec![6, 6]).is_ok());
///     assert!(shuffle_helper(vec![3, 3], vec![6, 3]).is_err());
///     // k=3
///     assert!(shuffle_helper(vec![3, 6, 10], vec![3, 6, 10]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![3, 10, 6]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![6, 3, 10]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![6, 10, 3]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![10, 3, 6]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![10, 6, 3]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![30, 6, 10]).is_err());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![3, 60, 10]).is_err());
///     assert!(shuffle_helper(vec![3, 6, 10], vec![3, 6, 100]).is_err());
///     // k=4
///     assert!(shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 15]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10, 15], vec![15, 6, 10, 3]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 3]).is_err());
///     // k=5
///     assert!(shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 17]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10, 15, 17], vec![10, 17, 3, 15, 6]).is_ok());
///     assert!(shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 3]).is_err());
/// }
///
/// fn shuffle_helper(input: Vec<u64>, output: Vec<u64>) -> Result<(), R1CSError> {
///     // Common
///     let pc_gens = PedersenGens::default();
///     let bp_gens = BulletproofGens::new(128, 1);
///
///     // Prover's scope
///     let (proof, commitments) = {
///         // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
///         // v and v_blinding empty because we are only testing low-level variable constraints
///         let v = vec![];
///         let v_blinding = vec![];
///         let mut prover_transcript = Transcript::new(b"ShuffleTest");
///         let (mut prover_cs, _variables, commitments) = ProverCS::new(
///             &bp_gens,
///             &pc_gens,
///             &mut prover_transcript,
///             v,
///             v_blinding.clone(),
///         );
///
///         // Prover allocates variables and adds constraints to the constraint system
///         let in_assignments = input
///             .iter()
///             .map(|in_i| Assignment::from(in_i.clone()))
///             .collect();
///         let out_assignments = output
///             .iter()
///             .map(|out_i| Assignment::from(out_i.clone()))
///             .collect();
///         shuffle_cs(&mut prover_cs, in_assignments, out_assignments)?;
///         let proof = prover_cs.prove()?;
///
///         (proof, commitments)
///     };
///
///     // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
///     let mut verifier_transcript = Transcript::new(b"ShuffleTest");
///     let (mut verifier_cs, _variables) =
///         VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);
///
///     // Verifier allocates variables and adds constraints to the constraint system
///     let in_assignments = input.iter().map(|_| Assignment::Missing()).collect();
///     let out_assignments = output.iter().map(|_| Assignment::Missing()).collect();
///     assert!(shuffle_cs(&mut verifier_cs, in_assignments, out_assignments,).is_ok());
///     // Verifier verifies proof
///     Ok(verifier_cs.verify(&proof)?)
/// }
///
/// fn shuffle_cs<CS: ConstraintSystem>(
///     cs: &mut CS,
///     input: Vec<Assignment>,
///     output: Vec<Assignment>,
/// ) -> Result<(), R1CSError> {
///     if input.len() != output.len() {
///         return Err(R1CSError::InvalidR1CSConstruction);
///     }
///     let k = input.len();
///     let mut in_pairs = Vec::with_capacity(k);
///     let mut out_pairs = Vec::with_capacity(k);
///
///     // Allocate pairs of low-level variables and their assignments
///     for i in 0..k / 2 {
///         let idx_l = i * 2;
///         let idx_r = idx_l + 1;
///         let (in_var_left, in_var_right) = cs.assign_uncommitted(input[idx_l], input[idx_r])?;
///         in_pairs.push((in_var_left, input[idx_l]));
///         in_pairs.push((in_var_right, input[idx_r]));
///
///         let (out_var_left, out_var_right) =
///             cs.assign_uncommitted(output[idx_l], output[idx_r])?;
///         out_pairs.push((out_var_left, output[idx_l]));
///         out_pairs.push((out_var_right, output[idx_r]));
///     }
///     if k % 2 == 1 {
///         let idx = k - 1;
///         let (in_var_left, _) = cs.assign_uncommitted(input[idx], Scalar::zero().into())?;
///         in_pairs.push((in_var_left, input[idx]));
///         let (out_var_left, _) = cs.assign_uncommitted(output[idx], Scalar::zero().into())?;
///         out_pairs.push((out_var_left, output[idx]));
///     }
///
///     KShuffleGadget::fill_cs(cs, in_pairs, out_pairs)
/// }
/// 
/// ```
///

pub mod r1cs {
    pub use circuit_proof::assignment::Assignment;
    pub use circuit_proof::prover::ProverCS;
    pub use circuit_proof::verifier::VerifierCS;
    pub use circuit_proof::ConstraintSystem;
    pub use circuit_proof::LinearCombination;
    pub use circuit_proof::R1CSProof;
    pub use circuit_proof::Variable;
    pub use errors::R1CSError;
}
