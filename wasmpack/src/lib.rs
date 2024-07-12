//! WASM-compatible verification wrappers

use dnssec_prover::ser::parse_rr_stream;
use dnssec_prover::validation::{verify_rr_stream, ValidationError};
use dnssec_prover::rr::Name;
use dnssec_prover::query::{ProofBuilder, ProofBuildingError, QueryBuf};

use wasm_bindgen::prelude::wasm_bindgen;

extern crate alloc;
use alloc::collections::VecDeque;

use core::fmt::Write;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
pub struct WASMProofBuilder(ProofBuilder, VecDeque<QueryBuf>, Option<ProofBuildingError>);

#[wasm_bindgen]
/// Builds a proof builder which can generate a proof for records of the given `ty`pe at the given
/// `name`.
///
/// After calling this [`get_next_query`] should be called to fetch the initial query.
pub fn init_proof_builder(mut name: String, ty: u16) -> Option<WASMProofBuilder> {
	if !name.ends_with('.') { name.push('.'); }
	if let Ok(qname) = name.try_into() {
		let (builder, initial_query) = ProofBuilder::new(&qname, ty);
		let mut queries = VecDeque::with_capacity(4);
		queries.push_back(initial_query);
		Some(WASMProofBuilder(builder, queries, None))
	} else {
		None
	}
}

#[wasm_bindgen]
/// Processes a response to a query previously fetched from [`get_next_query`].
///
/// After calling this, [`get_next_query`] should be called until pending queries are exhausted and
/// no more pending queries exist, at which point [`get_unverified_proof`] should be called.
pub fn process_query_response(proof_builder: &mut WASMProofBuilder, response: Vec<u8>) {
	if proof_builder.2.is_some() { return; }
	if response.len() < u16::MAX as usize {
		let mut answer = QueryBuf::new_zeroed(response.len() as u16);
		answer.copy_from_slice(&response);
		match proof_builder.0.process_response(&answer) {
			Ok(queries) =>
				for query in queries {
					proof_builder.1.push_back(query);
				}
			Err(e) => {
				proof_builder.2 = Some(e);
			}
		}
	}
}


#[wasm_bindgen]
/// Gets the next query (if any) that should be sent to the resolver for the given proof builder.
///
/// Once the resolver responds [`process_query_response`] should be called with the response.
pub fn get_next_query(proof_builder: &mut WASMProofBuilder) -> Option<Vec<u8>> {
	if proof_builder.2.is_some() { return None; }
	if let Some(query) = proof_builder.1.pop_front() {
		Some(query.into_vec())
	} else {
		None
	}
}

#[wasm_bindgen]
/// Gets the final, unverified, proof once all queries fetched via [`get_next_query`] have
/// completed and their responses passed to [`process_query_response`].
pub fn get_unverified_proof(proof_builder: WASMProofBuilder) -> Result<Vec<u8>, String> {
	if let Some(e) = proof_builder.2 {
		return Err(format!("{:?}", e));
	}
	proof_builder.0.finish_proof().map(|(proof, _ttl)| proof)
		.map_err(|()| "Too many queries required to build proof".to_string())
}

#[wasm_bindgen]
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
