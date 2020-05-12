#include "extension.hpp"

extern const sp_nativeinfo_t smcryptosocket_natives[];

class SocketNatives : public CryptoSockBase {
public:
    void OnExtLoad() {
        sharesys->AddNatives(myself, smcryptosocket_natives);
    }
};

SocketNatives natives;

static cell_t CreateCryptoSocket(IPluginContext *pContext, const cell_t *params) {
    return false;
}

const sp_nativeinfo_t smcryptosocket_natives[] = {
    {"CreateCryptoSocket", CreateCryptoSocket},
    {NULL, NULL}
};