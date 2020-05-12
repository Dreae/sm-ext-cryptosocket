#ifndef _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_

#include "smsdk_ext.h"

class CryptoSockets : public SDKExtension {
public:
    virtual bool SDK_OnLoad(char *error, size_t err_max, bool late);
    virtual void SDK_OnUnload();
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

#endif