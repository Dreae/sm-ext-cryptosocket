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

#pragma once
#include "extension.hpp"
#include <boost/asio.hpp>
#include <optional>
#include <atomic>

using boost::asio::ip::tcp;

using namespace std;

class encrypted_socket {
public:
    typedef function<void(uint8_t *, size_t)> data_callback;
    typedef function<void()> connect_callback;

    encrypted_socket(string key_id, string key, data_callback callback);
    ~encrypted_socket();
    void connect(optional<connect_callback> callback, string address, uint16_t  port);
    void set_disconnect_cb(connect_callback cb);
    void send(unique_ptr<uint8_t[]> data, size_t data_size);
    atomic<bool> connected;
private:
    void start_kx(optional<connect_callback> callback);
    void finish_kx(optional<connect_callback> callback);

    void start_msg_loop();
    void start_read_msg(data_callback callback);
    void do_read(uint16_t msg_size, data_callback callback);
    void check_ec(boost::system::error_code& ec);
    
    vector<uint8_t> derive_recv_keys();
    vector<uint8_t> derive_msg_keys();

    unique_ptr<tcp::socket> socket;
    unique_ptr<boost::asio::io_service::work> work;
    unique_ptr<boost::asio::streambuf> buffer;

    string key_id;
    char *key;
    size_t key_size;

    uint8_t *c_r;
    uint8_t *c_m;
    uint8_t *kx_pk;
    uint8_t *kx_sk;

    data_callback data_cb;
    optional<connect_callback> disconnected_cb;
};