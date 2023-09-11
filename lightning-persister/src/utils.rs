use lightning::util::persist::{KVSTORE_NAMESPACE_KEY_ALPHABET, KVSTORE_NAMESPACE_KEY_MAX_LEN};
use lightning::util::string::PrintableString;


pub(crate) fn is_valid_kvstore_str(key: &str) -> bool {
	key.len() <= KVSTORE_NAMESPACE_KEY_MAX_LEN && key.chars().all(|c| KVSTORE_NAMESPACE_KEY_ALPHABET.contains(c))
}

pub(crate) fn check_namespace_key_validity(namespace: &str, sub_namespace: &str, key: Option<&str>, operation: &str) -> Result<(), std::io::Error> {
	if let Some(key) = key {
		if key.is_empty() {
			debug_assert!(false, "Failed to {} {}/{}/{}: key may not be empty.", operation,
				PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
			let msg = format!("Failed to {} {}/{}/{}: key may not be empty.", operation,
				PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}

		if namespace.is_empty() && !sub_namespace.is_empty() {
			debug_assert!(false,
				"Failed to {} {}/{}/{}: namespace may not be empty if a non-empty sub-namespace is given.",
				operation,
				PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
			let msg = format!(
				"Failed to {} {}/{}/{}: namespace may not be empty if a non-empty sub-namespace is given.", operation,
				PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}

		if !is_valid_kvstore_str(namespace) || !is_valid_kvstore_str(sub_namespace) || !is_valid_kvstore_str(key) {
			debug_assert!(false, "Failed to {} {}/{}/{}: namespace, sub-namespace, and key must be valid.",
				operation,
				PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
			let msg = format!("Failed to {} {}/{}/{}: namespace, sub-namespace, and key must be valid.",
				operation,
				PrintableString(namespace), PrintableString(sub_namespace), PrintableString(key));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}
	} else {
		if namespace.is_empty() && !sub_namespace.is_empty() {
			debug_assert!(false,
				"Failed to {} {}/{}: namespace may not be empty if a non-empty sub-namespace is given.",
				operation, PrintableString(namespace), PrintableString(sub_namespace));
			let msg = format!(
				"Failed to {} {}/{}: namespace may not be empty if a non-empty sub-namespace is given.",
				operation, PrintableString(namespace), PrintableString(sub_namespace));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}
		if !is_valid_kvstore_str(namespace) || !is_valid_kvstore_str(sub_namespace) {
			debug_assert!(false, "Failed to {} {}/{}: namespace and sub-namespace must be valid.",
				operation, PrintableString(namespace), PrintableString(sub_namespace));
			let msg = format!("Failed to {} {}/{}: namespace and sub-namespace must be valid.",
				operation, PrintableString(namespace), PrintableString(sub_namespace));
			return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
		}
	}

	Ok(())
}
