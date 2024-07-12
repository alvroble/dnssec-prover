//! UniFFI-compatible verification wrappers

uniffi::include_scaffolding!("interface");

use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::{verify_rr_stream, ValidationError};
use dnssec_prover::rr::Name;
use dnssec_prover::query::ProofBuilder as NativeProofBuilder;
pub use dnssec_prover::query::ProofBuildingError;
use dnssec_prover::query::{QueryBuf};

use std::collections::VecDeque;
use std::fmt::Write;
use std::sync::{Arc, Mutex};

pub struct ProofBuilder(Mutex<(NativeProofBuilder, VecDeque<QueryBuf>)>);

/// Builds a proof builder which can generate a proof for records of the given `ty`pe at the given
/// `name`.
///
/// After calling this [`get_next_query`] should be called to fetch the initial query.
pub fn init_proof_builder(mut name: String, ty: u16) -> Option<Arc<ProofBuilder>> {
	if !name.ends_with('.') { name.push('.'); }
	if let Ok(qname) = name.try_into() {
		let (builder, initial_query) = NativeProofBuilder::new(&qname, ty);
		let mut queries = VecDeque::with_capacity(4);
		queries.push_back(initial_query);
		Some(Arc::new(ProofBuilder(Mutex::new((builder, queries)))))
	} else {
		None
	}
}

impl ProofBuilder {
	/// Processes a response to a query previously fetched from [`get_next_query`].
	///
	/// After calling this, [`get_next_query`] should be called until pending queries are exhausted and
	/// no more pending queries exist, at which point [`get_unverified_proof`] should be called.
	pub fn process_query_response(&self, response: Vec<u8>) -> Result<(), ProofBuildingError> {
		if response.len() < u16::MAX as usize {
			let mut answer = QueryBuf::new_zeroed(response.len() as u16);
			answer.copy_from_slice(&response);
			let mut us = self.0.lock().unwrap();
			let queries = us.0.process_response(&answer)?;
			for query in queries {
				us.1.push_back(query);
			}
		}
		Ok(())
	}

	/// Gets the next query (if any) that should be sent to the resolver for the given proof builder.
	///
	/// Once the resolver responds [`process_query_response`] should be called with the response.
	pub fn get_next_query(&self) -> Option<Vec<u8>> {
		if let Some(query) = self.0.lock().unwrap().1.pop_front() {
			Some(query.into_vec())
		} else {
			None
		}
	}

	/// Gets the final, unverified, proof once all queries fetched via [`get_next_query`] have
	/// completed and their responses passed to [`process_query_response`].
	pub fn get_unverified_proof(&self) -> Option<Vec<u8>> {
		self.0.lock().unwrap().0.clone().finish_proof().ok().map(|(proof, _ttl)| proof)
	}
}

/// Verifies an RFC 9102-formatted proof and returns verified records matching the given name
/// (resolving any C/DNAMEs as required).
pub fn verify_byte_stream(stream: Vec<u8>, name_to_resolve: String) -> String {
	let name = match Name::try_from(name_to_resolve) {
		Ok(name) => name,
		Err(()) => return "{\"error\":\"Bad name to resolve\"}".to_string(),
	};
	match do_verify_byte_stream(stream, name) {
		Ok(r) => r,
		Err(e) => format!("{{\"error\":\"{:?}\"}}", e),
	}
}

fn do_verify_byte_stream(stream: Vec<u8>, name_to_resolve: Name) -> Result<String, ValidationError> {
	let rrs = parse_rr_stream(&stream).map_err(|()| ValidationError::Invalid)?;
	let verified_rrs = verify_rr_stream(&rrs)?;
	let resolved_rrs = verified_rrs.resolve_name(&name_to_resolve);
	let mut resp = String::new();
	write!(&mut resp, "{}",
		format_args!("{{\"valid_from\": {}, \"expires\": {}, \"max_cache_ttl\": {}, \"verified_rrs\": [",
		verified_rrs.valid_from, verified_rrs.expires, verified_rrs.max_cache_ttl)
	).expect("Write to a String shouldn't fail");
	for (idx, rr) in resolved_rrs.iter().enumerate() {
		write!(&mut resp, "{}{}", if idx != 0 { ", " } else { "" }, rr.json())
			.expect("Write to a String shouldn't fail");
	}
	resp += "]}";
	Ok(resp)
}
