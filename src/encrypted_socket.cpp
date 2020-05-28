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

#include "encrypted_socket.hpp"
#include <sodium.h>
#include <boost/endian/conversion.hpp>
#include "crypto_ev.hpp"
#include "crypto.hpp"

#define CHAIN_KEY_SIZE crypto_auth_hmacsha512256_KEYBYTES
#define BLAKE2b_SIZE 64

encrypted_socket::encrypted_socket(string key_id, string key, data_callback data_cb) {
    this->socket = make_unique<tcp::socket>(event_loop.get_context());
    this->work = make_unique<boost::asio::io_context::work>(event_loop.get_context());
    this->buffer = nullptr;
    this->c_r = reinterpret_cast<uint8_t *>(sodium_malloc(CHAIN_KEY_SIZE));
    this->c_m = reinterpret_cast<uint8_t *>(sodium_malloc(CHAIN_KEY_SIZE));
    this->kx_pk = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_PUBLICKEYBYTES));
    this->kx_sk = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_SECRETKEYBYTES));
    this->connected.store(false);
    this->key_id = key_id;

    this->key = reinterpret_cast<char *>(sodium_malloc(key.size()));
    memcpy(this->key, key.c_str(), key.size());
    sodium_mprotect_noaccess(this->key);
    this->key_size = key.size();

    this->data_cb = data_cb;
}

encrypted_socket::~encrypted_socket() {
    sodium_free(this->key);
    sodium_free(this->kx_sk);
    sodium_free(this->kx_pk);
    sodium_free(this->c_r);
    sodium_free(this->c_m);
}

void encrypted_socket::connect(optional<connect_callback> callback, string address, uint16_t port) {
    // Maka new buffer in case we were interrupted
    this->buffer = unique_ptr<boost::asio::streambuf>(new boost::asio::streambuf());
    auto resolver = make_shared<tcp::resolver>(event_loop.get_context());

    char s_port[8];
    snprintf(s_port, sizeof(s_port), "%hu", port);
    tcp::resolver::query query(address.c_str(), s_port);
    
    extension.LogMessage("Resolving %s", address.c_str());
    resolver->async_resolve(query, [this, resolver, address, port, callback](boost::system::error_code ec, tcp::resolver::iterator i) {
        if (ec) {
            extension.LogError("Error resolving %s: %s", address.c_str(), ec.message().c_str());
        } else {
            tcp::endpoint ep(*i);
            this->socket->async_connect(ep, [this, address, port, callback](boost::system::error_code ec) {
                if (ec) {
                    extension.LogError("Error connecting to %s:%d: %s", address.c_str(), port, ec.message().c_str());
                } else {
                    extension.LogMessage("Connected to %s:%d", address.c_str(), port);
                    this->connected.store(true);
                    this->start_kx(callback);
                }
            });
        }
    });
}

void encrypted_socket::start_kx(optional<connect_callback> callback) {
    randombytes_buf(this->kx_sk, crypto_box_SECRETKEYBYTES);
    crypto_scalarmult_base(this->kx_pk, this->kx_sk);
    sodium_mprotect_noaccess(this->kx_sk);

    uint8_t salt[32];
    randombytes_buf(salt, sizeof(salt));

    vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(this->kx_pk), this->kx_pk + crypto_box_PUBLICKEYBYTES);
    buffer.insert(buffer.end(), salt, salt + 32);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t *>(this->key_id.c_str()), reinterpret_cast<const uint8_t *>(this->key_id.c_str()) + this->key_id.size());
    buffer.push_back(0);
    
    uint8_t derived_key[32];
    const uint8_t ctx[] = "SMCRYPTO_KEY";

    sodium_mprotect_readonly(this->key);
    hkdf(salt, sizeof(salt), reinterpret_cast<uint8_t *>(this->key), this->key_size, ctx, 12, derived_key, sizeof(derived_key));
    sodium_mprotect_noaccess(this->key);

    unsigned char mac[crypto_auth_BYTES];
    crypto_auth(mac, buffer.data(), buffer.size(), derived_key);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t *>(mac), reinterpret_cast<const uint8_t *>(mac) + crypto_auth_BYTES);

    uint16_t size = boost::endian::native_to_big(static_cast<uint16_t>(buffer.size()));
    buffer.insert(buffer.begin(), reinterpret_cast<uint8_t *>(&size), reinterpret_cast<uint8_t *>(&size) + 2);

    boost::asio::async_write(*this->socket, boost::asio::buffer(buffer), [this](boost::system::error_code ec, size_t n_written) {
        if (ec) {
            extension.LogMessage("Error during handshake: %s", ec.message().c_str());
        }
    });

    this->finish_kx(callback);
}

void encrypted_socket::finish_kx(optional<connect_callback> callback) {
    this->start_read_msg([this, callback](uint8_t *buffer, size_t msg_len) {
        auto server_kx_pk = reinterpret_cast<const unsigned char*>(buffer);
        auto salt = server_kx_pk + crypto_box_PUBLICKEYBYTES;
        auto server_key_id = reinterpret_cast<const char*>(salt) + 32;
        auto key_id_len = strlen(server_key_id);
        auto signature = reinterpret_cast<const unsigned char*>(server_key_id) + key_id_len + 1;

        uint8_t derived_key[32];
        const uint8_t d_ctx[] = "SMCRYPTO_KEY";

        sodium_mprotect_readonly(this->key);
        hkdf(salt, 32, reinterpret_cast<uint8_t *>(this->key), this->key_size, d_ctx, 12, derived_key, sizeof(derived_key));
        sodium_mprotect_noaccess(this->key);

        if (crypto_auth_verify(signature, server_kx_pk, crypto_box_PUBLICKEYBYTES + 32 + key_id_len + 1, derived_key) != 0) {
            extension.LogError("Hanshake error, signature mismatch");
            return;
        }

        sodium_mprotect_readonly(this->kx_sk);
        unsigned char scalarmult_shared_key[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(scalarmult_shared_key, this->kx_sk, server_kx_pk) != 0) {
            extension.LogError("Handshake error, scalarmult failed");
            sodium_mprotect_noaccess(this->kx_sk);
            return;
        }
        sodium_mprotect_noaccess(this->kx_sk);

        uint8_t session_key[CHAIN_KEY_SIZE * 2];
        const char ctx[] = "\x01";
        vector<uint8_t> sk_buf;
        sk_buf.insert(sk_buf.end(), scalarmult_shared_key, scalarmult_shared_key + crypto_scalarmult_BYTES);
        sk_buf.insert(sk_buf.end(), this->kx_pk, this->kx_pk + crypto_box_PUBLICKEYBYTES);
        sk_buf.insert(sk_buf.end(), server_kx_pk, server_kx_pk + crypto_box_PUBLICKEYBYTES);
        
        hkdf(NULL, 0, sk_buf.data(), sk_buf.size(), reinterpret_cast<const uint8_t *>(ctx), 1, session_key, sizeof(session_key));
        memcpy(this->c_r, session_key, CHAIN_KEY_SIZE);
        memcpy(this->c_m, session_key + CHAIN_KEY_SIZE, CHAIN_KEY_SIZE);

        sodium_mprotect_noaccess(this->c_r);
        sodium_mprotect_noaccess(this->c_m);

        if (callback.has_value()) {
            (*callback)();
        }

        this->start_msg_loop();
    });
}

void encrypted_socket::start_msg_loop() {
    this->start_read_msg([this](uint8_t *data, size_t size) {
        auto decrypted = reinterpret_cast<uint8_t *>(malloc(size));
        unsigned long long decrypted_len;

        vector<uint8_t> read_keys = this->derive_recv_keys();
        if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, 
                                                    NULL, data, size, 
                                                    reinterpret_cast<const unsigned char *>(this->key_id.c_str()), 
                                                    this->key_id.size(), read_keys.data() + 32, read_keys.data()) != 0) {
            extension.LogError("Failed to decrypt message; key_id: %s", this->key_id.c_str());
        } else {
            this->data_cb(decrypted, decrypted_len);
            free(decrypted);
        }

        this->start_msg_loop();
    });
}

void encrypted_socket::send(unique_ptr<uint8_t[]> data, size_t data_size) {
    unsigned char *ciphertext = reinterpret_cast<unsigned char *>(malloc(data_size + crypto_aead_chacha20poly1305_IETF_ABYTES));
    unsigned long long ciphertext_len;

    vector<uint8_t> write_keys = this->derive_msg_keys();
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len, 
                                         data.get(), data_size, 
                                         reinterpret_cast<const unsigned char *>(this->key_id.c_str()), 
                                         this->key_id.size(), NULL, write_keys.data() + 32, write_keys.data());

    uint16_t msg_len = boost::endian::native_to_big(static_cast<uint16_t>(ciphertext_len));

    vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<const char *>(&msg_len), reinterpret_cast<const char *>(&msg_len) + 2);
    buffer.insert(buffer.end(), reinterpret_cast<const char *>(ciphertext), reinterpret_cast<const char *>(ciphertext) + ciphertext_len);
    free(ciphertext);
    
    boost::asio::async_write(*this->socket, boost::asio::buffer(buffer), [this](boost::system::error_code ec, size_t n_written) {
        if (ec) {
            extension.LogMessage("Error sending message: %s", ec.message().c_str());
        }
    });
}

void advance_chain_key(uint8_t *chain_key) {
    const unsigned char in[] = "\x02";
    crypto_auth_hmacsha512256(chain_key, in, 1, chain_key);
}

vector<uint8_t> derive_keys(uint8_t *chain_key) {

    char ctx[] = "SMCRYPTO_KEYS";
    
    uint8_t keys[44];
    sodium_mprotect_readonly(chain_key);
    hkdf(NULL, 0, chain_key, CHAIN_KEY_SIZE, reinterpret_cast<uint8_t *>(ctx), 13, keys, sizeof(keys));
    sodium_mprotect_readwrite(chain_key);
    advance_chain_key(chain_key);
    sodium_mprotect_noaccess(chain_key);

    return vector(keys, keys + 44);
}

vector<uint8_t> encrypted_socket::derive_msg_keys() {
    return derive_keys(this->c_m);
}

vector<uint8_t> encrypted_socket::derive_recv_keys() {
    return derive_keys(this->c_r);
}

void encrypted_socket::start_read_msg(data_callback callback) {
    boost::asio::async_read(*this->socket, *this->buffer, boost::asio::transfer_exactly(2), [this, callback](boost::system::error_code ec, size_t n_bytes) {
        if (!ec) {
            uint16_t msg_size = *reinterpret_cast<const uint16_t *>(this->buffer->data().data());
            boost::endian::big_to_native_inplace(msg_size);
            this->do_read(msg_size, callback);
        } else {
            this->check_ec(ec);
            extension.LogError("Error reading packet: %s", ec.message().c_str());
        }
    });
}

void encrypted_socket::do_read(uint16_t msg_size, data_callback callback) {
    boost::asio::async_read(*this->socket, *this->buffer, boost::asio::transfer_exactly(msg_size), [this, msg_size, callback](boost::system::error_code ec, size_t n_bytes) {
        if (!ec) {
            auto buffer = reinterpret_cast<uint8_t *>(malloc(msg_size));
            memcpy(buffer, reinterpret_cast<const uint8_t *>(this->buffer->data().data()) + 2, msg_size);
            this->buffer = unique_ptr<boost::asio::streambuf>(new boost::asio::streambuf());

            callback(buffer, msg_size);
            free(buffer);
        } else {
            this->check_ec(ec);
            extension.LogError("Error reading packet: %s", ec.message().c_str());
            callback(NULL, 0);
        }
    });
}

void encrypted_socket::check_ec(boost::system::error_code& ec) {
    if (boost::asio::error::eof == ec || boost::asio::error::connection_reset == ec) {
        extension.LogMessage("Remote disconnected");
        this->connected.store(false);
        if (this->disconnected_cb.has_value()) {
            this->disconnected_cb->operator()();
        }
    }
}
