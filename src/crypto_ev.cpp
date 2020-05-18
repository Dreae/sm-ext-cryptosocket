#include "crypto_ev.hpp"

crypto_event_loop event_loop;

void ev_run() {
    event_loop.run();
}

void crypto_event_loop::OnExtLoad() {
    thread(ev_run).detach();
}

void crypto_event_loop::OnExtUnload() {
    this->context.stop();
}

void crypto_event_loop::run() {
    this->context.run();
}

boost::asio::io_context& crypto_event_loop::get_context() {
    return this->context;
}