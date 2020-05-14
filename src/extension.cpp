#include "extension.hpp"
#include "sodium.h"

CryptoSockets extension;
SMEXT_LINK(&extension);

CryptoSockBase *CryptoSockBase::head = NULL;

bool CryptoSockets::SDK_OnLoad(char *error, size_t err_max, bool late) {
    sodium_init();

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