#include "encrypted_socket.hpp"
#include "sodium.h"
#include <boost/endian/conversion.hpp>

encrypted_socket::encrypted_socket(string key_id, string key, data_callback data_cb) {
    this->service = make_unique<boost::asio::io_service>();
    this->socket = make_unique<tcp::socket>(*this->service);
    this->work = make_unique<boost::asio::io_service::work>(*this->service);
    this->buffer = unique_ptr<boost::asio::streambuf>(new boost::asio::streambuf());
    this->session_key = (uint8_t *)sodium_malloc(crypto_hash_sha512_BYTES);
    this->kx_pk = (uint8_t *)sodium_malloc(crypto_box_PUBLICKEYBYTES);
    this->kx_sk = (uint8_t *)sodium_malloc(crypto_box_SECRETKEYBYTES);
    this->connected = false;
    this->key_id = key_id;
    this->key = key;
    this->data_cb = data_cb;

    crypto_kdf_keygen(this->nonce_seed);
}

void encrypted_socket::connect(optional<connect_callback> callback, string address, uint16_t port) {
    auto resolver = make_shared<tcp::resolver>(*this->service);

    char s_port[8];
    snprintf(s_port, sizeof(s_port), "%hu", port);
    tcp::resolver::query query(address.c_str(), s_port);
    
    smutils->LogMessage(myself, "Resolving %s", address.c_str());
    auto self(shared_from_this());
    resolver->async_resolve(query, [this, self, resolver, address, port, callback](boost::system::error_code ec, tcp::resolver::iterator i) {
        if (ec) {
            smutils->LogError(myself, "Error resolving %s: %s", address.c_str(), ec.message().c_str());
        } else {
            tcp::endpoint ep(*i);
            this->socket->async_connect(ep, [this, self, address, port, callback](boost::system::error_code ec) {
                if (ec) {
                    smutils->LogError(myself, "Error connecting to %s:%d: %s", address.c_str(), port, ec.message().c_str());
                } else {
                    smutils->LogMessage(myself, "Connected to %s:%d", address.c_str(), port);
                    this->connected = true;
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

    boost::asio::streambuf buffer;
    ostream os(&buffer);
    os.write(reinterpret_cast<const char*>(this->kx_pk), crypto_box_PUBLICKEYBYTES);
    os.write(this->key_id.c_str(), this->key_id.size());
    os << '\0';
    
    unsigned char derived_key[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, reinterpret_cast<const unsigned char*>(this->key.c_str()), this->key.length());
    crypto_hash_sha512_final(&state, derived_key);

    unsigned char mac[crypto_auth_BYTES];
    crypto_auth(mac, boost::asio::buffer_cast<const unsigned char*>(buffer.data()), buffer.size(), derived_key);
    os.write(reinterpret_cast<const char*>(mac), crypto_auth_BYTES);

    auto self(shared_from_this());
    boost::asio::async_write(*this->socket, buffer, [this, self](boost::system::error_code ec, size_t n_written) {
        if (ec) {
            smutils->LogMessage(myself, "Error during handshake: %s", ec.message().c_str());
        }
    });

    this->finish_kx(callback);
}

void encrypted_socket::finish_kx(optional<connect_callback> callback) {
    auto self(shared_from_this());
    this->start_read_msg([this, self, callback](shared_ptr<uint8_t[]> buffer, size_t msg_len) {
        auto server_kx_pk = reinterpret_cast<const unsigned char*>(buffer.get());
        auto server_key_id = reinterpret_cast<const char*>(buffer.get() + crypto_box_PUBLICKEYBYTES);
        auto key_id_len = strlen(server_key_id);
        auto signature = reinterpret_cast<const unsigned char*>(buffer.get() + crypto_box_PUBLICKEYBYTES + key_id_len + 1);
        
        unsigned char derived_key[crypto_hash_sha512_BYTES];
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, reinterpret_cast<const unsigned char*>(this->key.c_str()), this->key.length());
        crypto_hash_sha512_final(&state, derived_key);

        if (crypto_auth_verify(signature, reinterpret_cast<const unsigned char*>(buffer.get()), crypto_box_PUBLICKEYBYTES + key_id_len + 1, derived_key) != 0) {
            smutils->LogError(myself, "Hanshake error, signature mismatch");
            return;
        }

        sodium_mprotect_readonly(this->kx_sk);
        unsigned char scalarmult_shared_key[crypto_scalarmult_BYTES];
        if (crypto_scalarmult(scalarmult_shared_key, this->kx_sk, server_kx_pk) != 0) {
            smutils->LogError(myself, "Handshake error, scalarmult failed");
            return;
        }

        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, scalarmult_shared_key, crypto_scalarmult_BYTES);
        crypto_hash_sha512_update(&state, this->kx_pk, crypto_box_PUBLICKEYBYTES);
        crypto_hash_sha512_update(&state, server_kx_pk, crypto_box_PUBLICKEYBYTES);
        crypto_hash_sha512_final(&state, this->session_key);

        sodium_mprotect_noaccess(this->session_key);
        sodium_free(this->kx_sk);
        sodium_free(this->kx_pk);

        if (callback.has_value()) {
            (*callback)();
        }
    });
}

void encrypted_socket::start_msg_loop() {
    auto self(shared_from_this());
    this->start_read_msg([this, self](shared_ptr<uint8_t[]> data, size_t size) {
        auto nonce = data.get();
        auto ciphertext = nonce + crypto_aead_chacha20poly1305_NPUBBYTES;
        auto ciphertext_len = this->msg_size - crypto_aead_chacha20poly1305_NPUBBYTES;
        auto decrypted = make_shared<uint8_t[]>(size);
        unsigned long long decrypted_len;

        sodium_mprotect_readonly(this->session_key);
        if (crypto_aead_chacha20poly1305_decrypt(decrypted.get(), &decrypted_len, 
                                                    NULL, ciphertext, ciphertext_len, 
                                                    reinterpret_cast<const unsigned char *>(this->key_id.c_str()), 
                                                    this->key_id.size(), nonce, this->session_key) != 0) {
            smutils->LogError(myself, "Failed to decrypt message; key_id: %s", this->key_id.c_str());
        } else {
            this->data_cb(decrypted, decrypted_len);
        }
        sodium_mprotect_noaccess(this->session_key);

        this->start_msg_loop();
    });
}

void encrypted_socket::send(unique_ptr<uint8_t[]> data, size_t data_size) {
    auto nonce = this->generate_nonce();
    unsigned char ciphertext[data_size + crypto_aead_chacha20poly1305_ABYTES];
    unsigned long long ciphertext_len;

    sodium_mprotect_readonly(this->session_key);
    crypto_aead_chacha20poly1305_encrypt(ciphertext, &ciphertext_len, 
                                         data.get(), data_size, 
                                         reinterpret_cast<const unsigned char *>(this->key_id.c_str()), 
                                         this->key_id.size(), NULL, nonce.get(), this->session_key);
    sodium_mprotect_noaccess(this->session_key);
    uint16_t msg_len = boost::endian::native_to_big(static_cast<uint16_t>(ciphertext_len + crypto_aead_chacha20poly1305_NPUBBYTES));

    boost::asio::streambuf buffer;
    ostream os(&buffer);
    os.write(reinterpret_cast<const char *>(&msg_len), 2);
    os.write(reinterpret_cast<const char *>(nonce.get()), crypto_aead_chacha20poly1305_NPUBBYTES);
    os.write(reinterpret_cast<const char *>(ciphertext), ciphertext_len);
    
    auto self(shared_from_this());
    boost::asio::async_write(*this->socket, buffer, [this, self](boost::system::error_code ec, size_t n_written) {
        if (ec) {
            smutils->LogMessage(myself, "Error sending message: %s", ec.message().c_str());
        }
    });
}

unique_ptr<uint8_t[]> encrypted_socket::generate_nonce() {
    this->nonce_counter++;
    auto nonce = make_unique<uint8_t[]>(crypto_aead_chacha20poly1305_NPUBBYTES);
    crypto_kdf_derive_from_key(nonce.get(), crypto_aead_chacha20poly1305_NPUBBYTES, this->nonce_counter, "noncekey", this->nonce_seed);

    return move(nonce);
}

void encrypted_socket::start_read_msg(data_callback callback) {
    auto self(shared_from_this());
    boost::asio::async_read(*this->socket, *this->buffer, boost::asio::transfer_exactly(2), [this, self, callback](boost::system::error_code ec, size_t n_bytes) {
        if (!ec) {
            this->msg_size = *boost::asio::buffer_cast<const uint16_t *>(this->buffer->data());
            boost::endian::big_to_native_inplace(this->msg_size);
            this->do_read(callback);
        } else {
            smutils->LogMessage(myself, "Error reading packet: %s", ec.message().c_str());
        }
    });
}

void encrypted_socket::do_read(data_callback callback) {
    auto self(shared_from_this());
    boost::asio::async_read(*this->socket, *this->buffer, boost::asio::transfer_exactly(this->msg_size), [this, self, callback](boost::system::error_code ec, size_t n_bytes) {
        if (!ec) {
            auto buffer = make_shared<uint8_t[]>(this->buffer->size());
            memcpy(buffer.get(), boost::asio::buffer_cast<const uint8_t *>(this->buffer->data()), this->buffer->size());
            this->buffer = unique_ptr<boost::asio::streambuf>(new boost::asio::streambuf());

            callback(buffer, this->buffer->size());
        } else {
            smutils->LogError(myself, "Error reading packet: %s", ec.message().c_str());
            callback(NULL, 0);
        }
    });
}
