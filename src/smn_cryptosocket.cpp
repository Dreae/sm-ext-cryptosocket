#include "extension.hpp"
#include "encrypted_socket.hpp"
#include "handletypes.hpp"
#include "crypto_ev.hpp"

extern const sp_nativeinfo_t smcryptosocket_natives[];
HandleType_t _encrypted_socket_handletype;

class socket_natives : public CryptoSockBase, public IHandleTypeDispatch {
public:
    void OnExtLoad() {
        HandleAccess hacc;
        TypeAccess tacc;
        handlesys->InitAccessDefaults(&tacc, &hacc);
        tacc.ident = myself->GetIdentity();
        hacc.access[HandleAccess_Read] = HANDLE_RESTRICT_OWNER;
        tacc.access[HTypeAccess_Create] = true;
        tacc.access[HTypeAccess_Inherit] = true;
        _encrypted_socket_handletype = handlesys->CreateType("EncryptedSocket", this, 0, &tacc, &hacc, myself->GetIdentity(), NULL);

        sharesys->AddNatives(myself, smcryptosocket_natives);
    }

    void OnExtUnload() {
        handlesys->RemoveType(_encrypted_socket_handletype, myself->GetIdentity());
    }

    void OnHandleDestroy(HandleType_t type, void *object) {
        delete reinterpret_cast<encrypted_socket *>(object);
    }

    bool GetHandleApproxSize(HandleType_t type, void *object, unsigned int *size) {
        auto socket = reinterpret_cast<encrypted_socket *>(object);
        *size = sizeof(socket);

        return true;
    }
};

socket_natives natives;

#define READ_HANDLE(pContext, params) \
    Handle_t hndl = static_cast<Handle_t>(params[1]); \
    HandleSecurity sec; \
    encrypted_socket *socket; \
    sec.pOwner = pContext->GetIdentity(); \
    sec.pIdentity = myself->GetIdentity(); \
    auto herr = handlesys->ReadHandle(hndl, _encrypted_socket_handletype, &sec, reinterpret_cast<void**>(&socket)); \
    if (herr != HandleError_None) { \
        pContext->ReportError("Invalid socket handle %x (error %d)", hndl, herr); \
        return 0; \
    }

static cell_t CreateEncryptedSocket(IPluginContext *pContext, const cell_t *params) {
    char *key_id, *key;
    pContext->LocalToString(params[1], &key_id);
    pContext->LocalToString(params[2], &key);
    auto callback = pContext->GetFunctionById((funcid_t)params[3]);
    if (!callback) {
        pContext->ReportError("Invalid handler callback provided");
        return 0;
    }
    
    auto socket = new encrypted_socket(string(key_id), string(key), [callback](shared_ptr<uint8_t[]> data, size_t size) {
        event_loop.add_event_callback([data, size, callback]() {
            callback->PushStringEx(reinterpret_cast<char *>(data.get()), size, SM_PARAM_STRING_BINARY, 0);
            callback->PushCell(size);
            callback->Execute(nullptr);
        });
    });
    auto hndl = handlesys->CreateHandle(_encrypted_socket_handletype, socket, pContext->GetIdentity(), myself->GetIdentity(), NULL);

    return hndl;
}

static cell_t EncryptedSocketConnect(IPluginContext *pContext, const cell_t *params) {
    READ_HANDLE(pContext, params);
    char *address;
    pContext->LocalToString(params[1], &address);
    uint16_t port = params[2];
    auto callback = pContext->GetFunctionById((funcid_t)params[3]);
    if (!callback) {
        socket->connect(nullopt, string(address), port);
        return 0;
    }

    socket->connect([callback]() {
        event_loop.add_event_callback([callback]() {
            callback->Execute(nullptr);
        });
    }, string(address), port);

    return 0;
}

const sp_nativeinfo_t smcryptosocket_natives[] = {
    {"CreateEncryptedSocket", CreateEncryptedSocket},
    {"EncryptedSocket.Connect", EncryptedSocketConnect},
    {NULL, NULL}
};