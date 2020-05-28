 /**
  * SourceMod Encrypted Socket Extension
  * Copyright (C) 2020  Dreae
  *
  * This program is free software: you can redistribute it and/or modify
  * it under the terms of the GNU General Public License as published by
  * the Free Software Foundation, either version 3 of the License, or
  * (at your option) any later version.
  *
  * This program is distributed in the hope that it will be useful,
  * but WITHOUT ANY WARRANTY; without even the implied warranty of
  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  * GNU General Public License for more details. 
  *
  * You should have received a copy of the GNU General Public License
  * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "crypto.hpp"
#include <math.h>
#include <memory.h>

void hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *key, size_t key_len, const uint8_t *ctx, size_t ctx_len, uint8_t *output, size_t output_len) {
    const uint8_t *salt_buf = salt;
    size_t slen = salt_len;
    if (salt_len == 0) {
        salt_buf = reinterpret_cast<uint8_t *>(calloc(crypto_auth_hmacsha512256_KEYBYTES, 1));
        slen = crypto_auth_hmacsha512256_KEYBYTES;
    }

    uint8_t *working_buffer = reinterpret_cast<uint8_t *>(malloc(crypto_auth_hmacsha512256_BYTES + ctx_len + 1));
    memcpy(working_buffer, reinterpret_cast<const void *>(ctx), ctx_len);
    working_buffer[ctx_len] = 1;

    uint8_t prk[crypto_auth_hmacsha512256_BYTES];
    crypto_auth_hmacsha512256_state state;
    crypto_auth_hmacsha512256_init(&state, salt_buf, slen);
    crypto_auth_hmacsha512256_update(&state, key, key_len);
    crypto_auth_hmacsha512256_final(&state, prk);

    crypto_auth_hmacsha512256_init(&state, prk, crypto_auth_hmacsha512256_BYTES);
    crypto_auth_hmacsha512256_update(&state, working_buffer, ctx_len + 1);
    crypto_auth_hmacsha512256_final(&state, working_buffer);
    if (output_len < crypto_auth_hmacsha512256_BYTES) {
        memcpy(output, working_buffer, output_len);
    } else {
        memcpy(output, working_buffer, crypto_auth_hmacsha512256_BYTES);
    }

    if (output_len > crypto_auth_hmacsha512256_BYTES) {
        int iterations = ceil(static_cast<float>(output_len) / static_cast<float>(crypto_auth_hmacsha512256_BYTES));
        memcpy(working_buffer + crypto_auth_hmacsha512256_BYTES, reinterpret_cast<const void *>(ctx), ctx_len);
        for (uint8_t c = 1; c < iterations; c++) {
            working_buffer[crypto_auth_hmacsha512256_BYTES + ctx_len] = c + 1;
            crypto_auth_hmacsha512256_init(&state, prk, crypto_auth_hmacsha512256_BYTES);
            crypto_auth_hmacsha512256_update(&state, working_buffer, crypto_auth_hmacsha512256_BYTES + ctx_len + 1);
            crypto_auth_hmacsha512256_final(&state, working_buffer);
            
            int bytes_generated = crypto_auth_hmacsha512256_BYTES * c;
            int remainder = output_len - bytes_generated;
            if (remainder > crypto_auth_hmacsha512256_BYTES) {
                remainder = crypto_auth_hmacsha512256_BYTES;
            }

            memcpy(output + bytes_generated, working_buffer, remainder);
        }
    }

    free(working_buffer);
    if (salt_len == 0) {
        free(const_cast<uint8_t *>(salt_buf));
    }
}