#pragma once
#include "extension.hpp"
#include <boost/asio.hpp>
#include <optional>

using boost::asio::ip::tcp;

using namespace std;

class encrypted_socket {
public:
    typedef function<void(shared_ptr<uint8_t[]>, size_t)> data_callback;
    typedef function<void()> connect_callback;

    encrypted_socket(string key_id, string key, data_callback callback);
    void connect(optional<connect_callback> callback, string address, uint16_t  port);
    void send(unique_ptr<uint8_t[]> data, size_t data_size);
    bool connected;
private:
    void start_kx(optional<connect_callback> callback);
    void finish_kx(optional<connect_callback> callback);

    void start_msg_loop();
    void start_read_msg(data_callback callback);
    void do_read(data_callback callback);

    unique_ptr<uint8_t[]> generate_nonce();

    unique_ptr<tcp::socket> socket;
    unique_ptr<boost::asio::io_service::work> work;
    unique_ptr<boost::asio::streambuf> buffer;

    string key_id;
    string key;
    uint8_t *session_key;
    uint8_t *kx_pk;
    uint8_t *kx_sk;

    uint32_t nonce_counter;
    uint8_t nonce_seed[32];

    size_t msg_size;
    data_callback data_cb;
};