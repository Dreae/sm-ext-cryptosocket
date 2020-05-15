#include "crypto_ev.hpp"

crypto_event_loop event_loop;

void execute_pending_callbacks(bool simulating) {
    event_loop.run();
}

void crypto_event_loop::OnExtLoad() {
    smutils->AddGameFrameHook(&execute_pending_callbacks);
}

void crypto_event_loop::add_event_callback(function<void()> callback) {
    this->mtx.lock();
    this->callbacks.push(callback);
    this->mtx.unlock();
}

void crypto_event_loop::run() {
    if (this->mtx.try_lock()) {
        while (!this->callbacks.empty()) {
            auto callback = this->callbacks.front();
            callback();

            this->callbacks.pop();
        }
        this->mtx.unlock();
    }
}