#pragma once
#include "extension.hpp"
#include <queue>
#include <functional>
#include <mutex>
#include <memory>
#include <boost/asio.hpp>

using namespace std;

class crypto_event_loop : public CryptoSockBase {
public:
    void OnExtLoad();
    void OnExtUnload();
    void run();

    crypto_event_loop() : work(context) { }
    boost::asio::io_context& get_context();
private:
    boost::asio::io_context context;
    boost::asio::io_context::work work;    
};

extern crypto_event_loop event_loop;