use lightning::util::logger::{Logger, Level, Record};

pub struct TestLogger {
	level: Level,
}

impl TestLogger {
	pub fn new() -> TestLogger {
		TestLogger {
			level: Level::Off,
		}
	}
	pub fn enable(&mut self, level: Level) {
		self.level = level;
	}
}

impl Logger for TestLogger {
	fn log(&self, record: &Record) {
		#[cfg(any(test, not(feature = "fuzztarget")))]
		println!("{:<5} [{} : {}, {}] {}", record.level.to_string(), record.module_path, record.file, record.line, record.args);
	}
}
