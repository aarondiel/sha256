#include "sha256.h"

typedef struct {
	uint32_t state[8];
	uint32_t message_schedule[64];
	uint64_t bit_length;

	uint32_t temporary_state[8];
	uint32_t temp_values[2];
} sha256_context;

static const uint32_t sha256_constants[64] = {
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2
};

static uint64_t sha256_big_endian64(uint64_t value) {
	uint8_t *value_byte_array = (uint8_t *)&value;
	uint8_t new_value[8] = {
		value_byte_array[7],
		value_byte_array[6],
		value_byte_array[5],
		value_byte_array[4],
		value_byte_array[3],
		value_byte_array[2],
		value_byte_array[1],
		value_byte_array[0]
	};

	return *(uint64_t *)new_value;
}

static uint32_t sha256_big_endian32(uint32_t value) {
	uint8_t *value_byte_array = (uint8_t *)&value;
	uint8_t new_value[4] = {
		value_byte_array[3],
		value_byte_array[2],
		value_byte_array[1],
		value_byte_array[0]
	};

	return *(uint32_t *)new_value;
}

static inline uint32_t sha256_right_shift(uint32_t value, uint8_t shift) {
	return value >> shift;
}

static inline uint32_t sha256_left_shift(uint32_t value, uint8_t shift) {
	return value << shift;
}

static inline uint32_t sha256_rotation_right(uint32_t value, uint8_t shift) {
	return (
		sha256_right_shift(value, shift) |
		sha256_left_shift(value, 32 - shift)
	);
}

static inline uint32_t sha256_lower_sigma0(uint32_t value) {
	return (
		sha256_rotation_right(value, 7) ^
		sha256_rotation_right(value, 18) ^
		sha256_right_shift(value, 3)
	);
}

static inline uint32_t sha256_lower_sigma1(uint32_t value) {
	uint32_t v = (
		sha256_rotation_right(value, 17) ^
		sha256_rotation_right(value, 19) ^
		sha256_right_shift(value, 10)
	);

	return v;
}

static inline uint32_t sha256_upper_sigma0(uint32_t value) {
	return (
		sha256_rotation_right(value, 2) ^
		sha256_rotation_right(value, 13) ^
		sha256_rotation_right(value, 22)
	);
}

static inline uint32_t sha256_upper_sigma1(uint32_t value) {
	return (
		sha256_rotation_right(value, 6) ^
		sha256_rotation_right(value, 11) ^
		sha256_rotation_right(value,25)
	);
}

static inline uint32_t sha256_choice(uint32_t value1, uint32_t value2, uint32_t value3) {
	return (
		(value1 & value2) ^
		(~value1 & value3)
	);
}

static inline uint32_t sha256_majority(uint32_t value1, uint32_t value2, uint32_t value3) {
	return (
		(value1 & value2) ^
		(value1 & value3) ^
		(value2 & value3)
	);
}

static void sha256_fill_message_schedule(sha256_context *context) {
	for (uint8_t i = 0; i < 16; i++)
		context->message_schedule[i] = sha256_big_endian32(context->message_schedule[i]);

	for (uint8_t i = 16; i < 64; i++) {
		context->message_schedule[i] = (
			sha256_lower_sigma1(context->message_schedule[i - 2]) +
			context->message_schedule[i - 7] +
			sha256_lower_sigma0(context->message_schedule[i - 15]) +
			context->message_schedule[i - 16]
		);
	}
}

static void sha256_transform(sha256_context *context) {
	sha256_fill_message_schedule(context);

	memcpy(
		context->temporary_state,
		context->state,
		8 * sizeof(uint32_t)
	);

	for (uint8_t i = 0; i < 64; i++) {
		context->temp_values[0] = (
			sha256_upper_sigma1(context->temporary_state[4]) +
			sha256_choice(
				context->temporary_state[4],
				context->temporary_state[5],
				context->temporary_state[6]
			) +
			context->temporary_state[7] +
			sha256_constants[i] +
			context->message_schedule[i]
		);

		context->temp_values[1] = (
			sha256_upper_sigma0(context->temporary_state[0]) +
			sha256_majority(
				context->temporary_state[0],
				context->temporary_state[1],
				context->temporary_state[2]
			)
		);

		context->temporary_state[7] = context->temporary_state[6];
		context->temporary_state[6] = context->temporary_state[5];
		context->temporary_state[5] = context->temporary_state[4];
		context->temporary_state[4] = context->temporary_state[3] + context->temp_values[0];
		context->temporary_state[3] = context->temporary_state[2];
		context->temporary_state[2] = context->temporary_state[1];
		context->temporary_state[1] = context->temporary_state[0];
		context->temporary_state[0] = context->temp_values[0] + context->temp_values[1];
	}

	context->state[0] += context->temporary_state[0];
	context->state[1] += context->temporary_state[1];
	context->state[2] += context->temporary_state[2];
	context->state[3] += context->temporary_state[3];
	context->state[4] += context->temporary_state[4];
	context->state[5] += context->temporary_state[5];
	context->state[6] += context->temporary_state[6];
	context->state[7] += context->temporary_state[7];
}

void sha256(sha256_hash hash, uint8_t *data, size_t length) {
	sha256_context context = {
		.bit_length = 0,
		.message_schedule = { 0 },
		.state = {
			0x6a09e667,
			0xbb67ae85,
			0x3c6ef372,
			0xa54ff53a,
			0x510e527f,
			0x9b05688c,
			0x1f83d9ab,
			0x5be0cd19
		}
	};

	while (length > 64) {
		memcpy(context.message_schedule, data, 64);
		context.bit_length += 512;
		data = &data[64];
		length -= 64;

		sha256_transform(&context);
	}

	memcpy(context.message_schedule, data, length);
	context.bit_length += length * 8;

	uint8_t *message_schedule_end = (uint8_t *)context.message_schedule + length;
	*message_schedule_end = 0x80;
	message_schedule_end += 1;

	memset(
		message_schedule_end,
		0,
		64 - length - 1
	);

	if (length > 54) {
		sha256_transform(&context);
		memset(context.message_schedule, 0, 64);
	}

	uint64_t *message_schedule_size = (uint64_t *)&context.message_schedule[14];
	*message_schedule_size = sha256_big_endian64(context.bit_length);
	sha256_transform(&context);

	memcpy(hash, context.state, 8 * sizeof(uint32_t));
}

void sha256_print(sha256_hash hash) {
	for (uint8_t i = 0; i < 8; i++) {
		printf("%x", hash[i]);
	}

	printf("\n");
}

int main(int argc, char **argv) {
	if (argc == 1)
		return 1;

	sha256_hash hash;
	sha256(hash, (uint8_t *)argv[1], strlen(argv[1]));
	sha256_print(hash);
}
