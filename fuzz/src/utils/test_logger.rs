use lightning::util::logger::{Logger, Record};
pub struct TestLogger {
	#[cfg(test)]
	id: String,
}

impl TestLogger {
	pub fn new(_id: String) -> TestLogger {
		TestLogger {
			#[cfg(test)]
			id: _id
		}
	}
}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		#[cfg(test)]
		println!("{:<5} {} [{} : {}, {}] {}", record.level.to_string(), self.id, record.module_path, record.file, record.line, record.args);
		#[cfg(not(test))]
		let _ = format!("{}", record.args);
	}
}
