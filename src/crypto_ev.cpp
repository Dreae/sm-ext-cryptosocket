#include "crypto_ev.hpp"

crypto_event_loop event_loop;

void ev_run(bool simulating) {
    event_loop.run();
}

void crypto_event_loop::OnExtLoad() {
    smutils->AddGameFrameHook(&ev_run);
}

void crypto_event_loop::add_event_callback(function<void()> callback) {
    this->mtx.lock();
    this->callbacks.push(callback);
    this->mtx.unlock();
}

void crypto_event_loop::add_service(shared_ptr<crypto_io_service> service) {
    this->mtx.lock();
    this->services.push_back(service);
    this->mtx.unlock();
}

void crypto_event_loop::run() {
    if (this->mtx.try_lock()) {
        while (!this->callbacks.empty()) {
            auto callback = this->callbacks.front();
            callback();

            this->callbacks.pop();
        }

        for (auto service : this->services) {
            service->poll();
        }

        this->mtx.unlock();
    }
}