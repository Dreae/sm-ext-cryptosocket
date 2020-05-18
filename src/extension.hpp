#pragma once
#include "smsdk_ext.h"
#include <memory>
#include <functional>

class CryptoSockets : public SDKExtension {
public:
    virtual bool SDK_OnLoad(char *error, size_t err_max, bool late);
    virtual void SDK_OnUnload();
    virtual void LogMessage(const char *msg, ...);
    virtual void LogError(const char *msg, ...);
    virtual void Defer(std::function<void()> callback);
};

class CryptoSockBase {
    friend class CryptoSockets;

public:
    CryptoSockBase() {
        next = CryptoSockBase::head;
        CryptoSockBase::head = this;
    }

    virtual void OnExtLoad() { };
    virtual void OnExtUnload() { };
private:
    CryptoSockBase *next;
    static CryptoSockBase *head;
};

extern CryptoSockets extension;
