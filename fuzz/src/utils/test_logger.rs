// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

use lightning::util::logger::{Logger, Record};
use std::sync::{Arc, Mutex};
use std::io::Write;

pub trait Output : Clone  + 'static {
	fn locked_write(&self, data: &[u8]);
}

#[derive(Clone)]
pub struct DevNull {}
impl Output for DevNull {
	fn locked_write(&self, _data: &[u8]) {}
}
#[derive(Clone)]
pub struct StringBuffer(Arc<Mutex<String>>);
impl Output for StringBuffer {
	fn locked_write(&self, data: &[u8]) {
		self.0.lock().unwrap().push_str(&String::from_utf8(data.to_vec()).unwrap());
	}
}
impl StringBuffer {
	pub fn new() -> Self {
		Self(Arc::new(Mutex::new(String::new())))
	}
	pub fn into_string(self) -> String {
		Arc::try_unwrap(self.0).unwrap().into_inner().unwrap()
	}
}

pub struct TestLogger<Out : Output> {
	id: String,
	out: Out,
}
impl<Out: Output> TestLogger<Out> {
	pub fn new(id: String, out: Out) -> TestLogger<Out> {
		TestLogger { id, out }
	}
}

struct LockedWriteAdapter<'a, Out: Output>(&'a Out);
impl<'a, Out: Output> Write for LockedWriteAdapter<'a, Out> {
	fn write(&mut self, data: &[u8]) -> Result<usize, std::io::Error> {
		self.0.locked_write(data);
		Ok(data.len())
	}
	fn flush(&mut self) -> Result<(), std::io::Error> { Ok(()) }
}

impl<Out: Output> Logger for TestLogger<Out> {
	fn log(&self, record: &Record) {
		write!(LockedWriteAdapter(&self.out),
			"{:<5} {} [{} : {}] {}\n", record.level.to_string(), self.id, record.module_path, record.line, record.args)
			.unwrap();
	}
}
