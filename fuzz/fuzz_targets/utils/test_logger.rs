use lightning::util::logger::{Logger, Record};

pub struct TestLogger {}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		#[cfg(test)]
		println!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
		#[cfg(not(test))]
		let _ = format!("{}", record.args);
	}
}
