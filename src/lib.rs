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
/// fn main() {
/// }
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
