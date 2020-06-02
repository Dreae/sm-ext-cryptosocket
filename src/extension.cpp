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

#include "extension.hpp"
#include <sodium.h>
#include <atomic>

CryptoSockets extension;
SMEXT_LINK(&extension);

CryptoSockBase *CryptoSockBase::head = NULL;
std::atomic<bool> unloaded;

bool CryptoSockets::SDK_OnLoad(char *error, size_t err_max, bool late) {
    int sodium_res;
    if ((sodium_res = sodium_init()) < 0) {
        sprintf(error, "Error initializing sodium (err %d)", sodium_res);
    }

    CryptoSockBase *head = CryptoSockBase::head;
    while (head) {
        head->OnExtLoad();
        head = head->next;
    }
    
    unloaded.store(false);
    return true;
}

void CryptoSockets::SDK_OnUnload() {
    CryptoSockBase *head = CryptoSockBase::head;
    while (head) {
        head->OnExtUnload();
        head = head->next;
    }

    unloaded.store(true);
}

void log_msg(void *msg) {
    if (!unloaded.load()) {
        smutils->LogMessage(myself, reinterpret_cast<char *>(msg));
    }
    free(msg);
}


void log_err(void *msg) {
    if (!unloaded.load()) {
        smutils->LogError(myself, reinterpret_cast<char *>(msg));
    }
    free(msg);
}

void CryptoSockets::LogMessage(const char *msg, ...) {
    char *buffer = reinterpret_cast<char *>(malloc(3072));
    va_list vp;
    va_start(vp, msg);
    vsnprintf(buffer, 3072, msg, vp);
    va_end(vp);

    smutils->AddFrameAction(&log_msg, reinterpret_cast<void *>(buffer));
}

void CryptoSockets::LogError(const char *msg, ...) {
    char *buffer = reinterpret_cast<char *>(malloc(3072));
    va_list vp;
    va_start(vp, msg);
    vsnprintf(buffer, 3072, msg, vp);
    va_end(vp);
    
    smutils->AddFrameAction(&log_err, reinterpret_cast<void *>(buffer));
}

void execute_cb(void *cb) {
    std::unique_ptr<std::function<void()>> callback(reinterpret_cast<std::function<void()> *>(cb));
    callback->operator()();
}

void CryptoSockets::Defer(std::function<void()> callback) {
    std::unique_ptr<std::function<void()>> cb = std::make_unique<std::function<void()>>(callback);
    smutils->AddFrameAction(&execute_cb, cb.release());
}