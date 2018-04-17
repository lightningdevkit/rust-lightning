#include <stdint.h>
#include <stdlib.h>

uint32_t rust_crypto_util_fixed_time_eq_asm(uint8_t* lhsp, uint8_t* rhsp, size_t count) {
	if (count == 0) {
		return 1;
	}
	uint8_t result = 0;
	for (size_t i = 0; i < count; i++) {
		result |= (lhsp[i] ^ rhsp[i]);
	}
	return result;
}
