#include "encrypted_socket.hpp"

encrypted_socket::encrypted_socket(string key) {
    this->service = make_unique<boost::asio::io_service>();
    this->socket = make_unique<tcp::socket>(*this->service);
    this->work = make_unique<boost::asio::io_service::work>(*this->service);
    this->buffer = make_unique<boost::asio::streambuf>();
    this->connected = false;
}

void encrypted_socket::connect(function<void()> callback, string address, uint16_t port) {
    auto resolver = make_shared<tcp::resolver>(*this->service);

    char s_port[8];
    snprintf(s_port, sizeof(s_port), "%hu", port);
    tcp::resolver::query query(address.c_str(), s_port);
    
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
                    if (callback) {
                        callback();
                    }

                    this->start_read_packet();
                }
            });
        }
    });
}

void encrypted_socket::start_read_packet() {
    auto self(shared_from_this());
    
    boost::asio::async_read(*this->socket, *this->buffer, boost::asio::transfer_exactly(2), [this, self](boost::system::error_code ec, size_t n_bytes) {
        if (!ec) {
            this->msg_size = *boost::asio::buffer_cast<const uint16_t *>(this->buffer->data());
            this->do_read();
        } else {
            smutils->LogMessage(myself, "Error reading packet: %s", ec.message().c_str());
            this->start_read_packet();
        }
    });
}

void encrypted_socket::do_read() {
    auto self(shared_from_this());

    boost::asio::async_read(*this->socket, *this->buffer, boost::asio::transfer_exactly(this->msg_size), [this, self](boost::system::error_code ec, size_t n_bytes) {
        if (!ec) {
            // TODO: Stuff with data
        } else {
            smutils->LogError(myself, "Error reading packet: %s", ec.message().c_str());
        }

        this->start_read_packet();
    });
}
