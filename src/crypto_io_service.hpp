#pragma once
#include <memory>
#include <boost/asio.hpp>

class crypto_io_service {
protected:
    std::unique_ptr<boost::asio::io_service> service;
public:
    void poll() {
        this->service->poll();
    }
};