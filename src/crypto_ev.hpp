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