#include "extension.hpp"
#include "sodium.h"

CryptoSockets extension;
SMEXT_LINK(&extension);

CryptoSockBase *CryptoSockBase::head = NULL;

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
    
    return true;
}

void CryptoSockets::SDK_OnUnload() {
    CryptoSockBase *head = CryptoSockBase::head;
    while (head) {
        head->OnExtUnload();
        head = head->next;
    }
}

void log_msg(void *msg) {
    smutils->LogMessage(myself, reinterpret_cast<char *>(msg));
    free(msg);
}


void log_err(void *msg) {
    smutils->LogError(myself, reinterpret_cast<char *>(msg));
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