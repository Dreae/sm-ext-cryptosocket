#pragma once
#include <sodium.h>

void hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *key, size_t key_len, const uint8_t *ctx, size_t ctx_len, uint8_t *output, size_t output_len);