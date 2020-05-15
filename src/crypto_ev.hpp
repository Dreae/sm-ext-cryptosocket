#pragma once
#include "extension.hpp"
#include <queue>
#include <functional>
#include <mutex>

using namespace std;

class crypto_event_loop : public CryptoSockBase {
public:
    void add_event_callback(function<void()> callback);
    void OnExtLoad();
    void run();
private:
    mutex mtx;
    queue<function<void()>> callbacks;
};

extern crypto_event_loop event_loop;