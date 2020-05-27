#include "encrypted_socket.hpp"
#include <sodium.h>
#include <boost/endian/conversion.hpp>
#include "crypto_ev.hpp"

#define BLAKE2b_SIZE 64

encrypted_socket::encrypted_socket(string key_id, string key, data_callback data_cb) {
    this->socket = make_unique<tcp::socket>(event_loop.get_context());
    this->work = make_unique<boost::asio::io_context::work>(event_loop.get_context());
    this->buffer = nullptr;
    this->session_key = reinterpret_cast<uint8_t *>(sodium_malloc(BLAKE2b_SIZE));
    this->kx_pk = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_PUBLICKEYBYTES));
    this->kx_sk = reinterpret_cast<uint8_t *>(sodium_malloc(crypto_box_SECRETKEYBYTES));
    this->connected.store(false);
    this->key_id = key_id;

    this->key = reinterpret_cast<char *>(sodium_malloc(key.size()));
    memcpy(this->key, key.c_str(), key.size());
    sodium_mprotect_noaccess(this->key);
    this->key_size = key.size();

    this->data_cb = data_cb;

    randombytes_buf(this->nonce_seed, sizeof(this->nonce_seed));
}

encrypted_socket::~encrypted_socket() {
    sodium_free(this->key);
    sodium_free(this->kx_sk);
    sodium_free(this->kx_pk);
    sodium_free(this->session_key);
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

    vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<uint8_t *>(this->kx_pk), this->kx_pk + crypto_box_PUBLICKEYBYTES);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t *>(this->key_id.c_str()), reinterpret_cast<const uint8_t *>(this->key_id.c_str()) + this->key_id.size());
    buffer.push_back(0);
    
    unsigned char derived_key[BLAKE2b_SIZE];

    sodium_mprotect_readonly(this->key);
    crypto_generichash(derived_key, BLAKE2b_SIZE, reinterpret_cast<const unsigned char*>(this->key), this->key_size, NULL, 0);
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
        auto server_key_id = reinterpret_cast<const char*>(server_kx_pk) + crypto_box_PUBLICKEYBYTES;
        auto key_id_len = strlen(server_key_id);
        auto signature = reinterpret_cast<const unsigned char*>(server_key_id) + key_id_len + 1;

        unsigned char derived_key[BLAKE2b_SIZE];
        crypto_generichash_state state;
        crypto_generichash_init(&state, NULL, 0, BLAKE2b_SIZE);
        
        sodium_mprotect_readonly(this->key);
        crypto_generichash_update(&state, reinterpret_cast<const unsigned char*>(this->key), this->key_size);
        sodium_mprotect_noaccess(this->key);

        crypto_generichash_final(&state, derived_key, BLAKE2b_SIZE);

        if (crypto_auth_verify(signature, server_kx_pk, crypto_box_PUBLICKEYBYTES + key_id_len + 1, derived_key) != 0) {
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

        crypto_generichash_init(&state, NULL, 0, BLAKE2b_SIZE);
        crypto_generichash_update(&state, scalarmult_shared_key, crypto_scalarmult_BYTES);
        crypto_generichash_update(&state, this->kx_pk, crypto_box_PUBLICKEYBYTES);
        crypto_generichash_update(&state, server_kx_pk, crypto_box_PUBLICKEYBYTES);
        crypto_generichash_final(&state, this->session_key, BLAKE2b_SIZE);

        sodium_mprotect_noaccess(this->session_key);

        if (callback.has_value()) {
            (*callback)();
        }

        this->start_msg_loop();
    });
}

void encrypted_socket::start_msg_loop() {
    this->start_read_msg([this](uint8_t *data, size_t size) {
        auto nonce = data;
        auto ciphertext = nonce + crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
        auto ciphertext_len = size - crypto_aead_chacha20poly1305_IETF_NPUBBYTES;
        auto decrypted = reinterpret_cast<uint8_t *>(malloc(size));
        unsigned long long decrypted_len;

        sodium_mprotect_readonly(this->session_key);
        if (crypto_aead_chacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, 
                                                    NULL, ciphertext, ciphertext_len, 
                                                    reinterpret_cast<const unsigned char *>(this->key_id.c_str()), 
                                                    this->key_id.size(), nonce, this->session_key) != 0) {
            extension.LogError("Failed to decrypt message; key_id: %s", this->key_id.c_str());
        } else {
            this->data_cb(decrypted, decrypted_len);
            free(decrypted);
        }
        sodium_mprotect_noaccess(this->session_key);

        this->start_msg_loop();
    });
}

void encrypted_socket::send(unique_ptr<uint8_t[]> data, size_t data_size) {
    auto nonce = this->generate_nonce();
    unsigned char *ciphertext = reinterpret_cast<unsigned char *>(malloc(data_size + crypto_aead_chacha20poly1305_IETF_ABYTES));
    unsigned long long ciphertext_len;

    sodium_mprotect_readonly(this->session_key);
    crypto_aead_chacha20poly1305_ietf_encrypt(ciphertext, &ciphertext_len, 
                                         data.get(), data_size, 
                                         reinterpret_cast<const unsigned char *>(this->key_id.c_str()), 
                                         this->key_id.size(), NULL, nonce.data(), this->session_key);
    sodium_mprotect_noaccess(this->session_key);
    uint16_t msg_len = boost::endian::native_to_big(static_cast<uint16_t>(ciphertext_len + crypto_aead_chacha20poly1305_IETF_NPUBBYTES));

    vector<uint8_t> buffer;
    buffer.insert(buffer.end(), reinterpret_cast<const char *>(&msg_len), reinterpret_cast<const char *>(&msg_len) + 2);
    buffer.insert(buffer.end(), nonce.begin(), nonce.begin() + crypto_aead_chacha20poly1305_IETF_NPUBBYTES);
    buffer.insert(buffer.end(), reinterpret_cast<const char *>(ciphertext), reinterpret_cast<const char *>(ciphertext) + ciphertext_len);
    free(ciphertext);
    
    boost::asio::async_write(*this->socket, boost::asio::buffer(buffer), [this](boost::system::error_code ec, size_t n_written) {
        if (ec) {
            extension.LogMessage("Error sending message: %s", ec.message().c_str());
        }
    });
}

vector<uint8_t> encrypted_socket::generate_nonce() {
    uint32_t counter = this->nonce_counter.fetch_add(1, memory_order_acq_rel);
    vector<uint8_t> nonce;
    nonce.reserve(crypto_hash_sha512_BYTES);

    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, this->nonce_seed, sizeof(this->nonce_seed));
    crypto_hash_sha512_update(&state, reinterpret_cast<unsigned char *>(&counter), 4);
    crypto_hash_sha512_final(&state, nonce.data());

    return nonce;
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
