fn main() {
	let mut iter = std::env::args();
	iter.next().unwrap(); // program name
	let path = iter.next().expect("Requires a path as the first argument");
	lightning_fuzz::full_stack::write_fst_seeds(&path);
}
