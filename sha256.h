#pragma once

#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef uint32_t sha256_hash[8];

void sha256(sha256_hash hash, uint8_t *data, size_t length);
void sha256_print(sha256_hash hash);
