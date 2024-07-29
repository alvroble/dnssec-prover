use dnssec_prover::{ser, validation};

use std::io::Read;

fn main() {
	let mut input =  Vec::new();
	std::io::stdin().lock().read_to_end(&mut input).unwrap();
	let val = ser::parse_rr_stream(&input).unwrap();
	validation::verify_rr_stream(&val).unwrap();
}
