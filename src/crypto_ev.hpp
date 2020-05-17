#pragma once
#include "extension.hpp"
#include <queue>
#include <functional>
#include <mutex>
#include "crypto_io_service.hpp"
#include <memory>

using namespace std;

class crypto_event_loop : public CryptoSockBase {
public:
    void add_event_callback(function<void()> callback);
    void add_service(shared_ptr<crypto_io_service> service);
    void OnExtLoad();
    void run();
private:
    mutex mtx;
    queue<function<void()>> callbacks;
    vector<shared_ptr<crypto_io_service>> services;
};

extern crypto_event_loop event_loop;