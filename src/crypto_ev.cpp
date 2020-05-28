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