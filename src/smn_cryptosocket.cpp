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
    
    auto socket = new encrypted_socket(string(key_id), string(key), [callback](uint8_t *data, size_t size) {
        auto data_copy = reinterpret_cast<uint8_t *>(malloc(size));
        memcpy(data_copy, data, size);
        extension.Defer([data_copy, size, callback]() {
            callback->PushStringEx(reinterpret_cast<char *>(data_copy), size, SM_PARAM_STRING_BINARY | SM_PARAM_STRING_COPY, 0);
            callback->PushCell(size);
            callback->Execute(nullptr);

            free(data_copy);
        });
    });

    auto hndl = handlesys->CreateHandle(_encrypted_socket_handletype, socket, pContext->GetIdentity(), myself->GetIdentity(), NULL);

    return hndl;
}

static cell_t EncryptedSocketConnect(IPluginContext *pContext, const cell_t *params) {
    READ_HANDLE(pContext, params);
    char *address;
    pContext->LocalToString(params[2], &address);
    uint16_t port = params[3];
    auto handle = params[1];
    auto callback = pContext->GetFunctionById((funcid_t)params[4]);

    auto addr = string(address);
    smutils->LogMessage(myself, "Attempting to connect to %s:%d", addr.c_str(), port);
    if (!callback) {
        socket->connect(nullopt, addr, port);
    } else {
        socket->connect([callback, handle]() {
            extension.Defer([callback, handle]() {
                callback->PushCell(handle);
                callback->Execute(nullptr);
            });
        }, addr, port);
    }


    return 0;
}

static cell_t EncryptedSocketSend(IPluginContext *pContext, const cell_t *params) {
    READ_HANDLE(pContext, params);
    if (!socket->connected.load()) {
        pContext->ReportError("Socket is not connected");
    }
    uint8_t *data;
    pContext->LocalToPhysAddr(params[2], reinterpret_cast<cell_t **>(&data));
    auto data_size = params[3];
    auto data_copy = make_unique<uint8_t[]>(data_size);
    memcpy(data_copy.get(), data, data_size);

    socket->send(move(data_copy), data_size);

    return 0;
}

static cell_t EncryptedSocketConnected(IPluginContext *pContext, const cell_t *params) {
    READ_HANDLE(pContext, params);
    return socket->connected.load();
}

static cell_t EncryptedSocketOnDisconnected(IPluginContext *pContext, const cell_t *params) {
    READ_HANDLE(pContext, params);
    auto handle = params[1];
    auto callback = pContext->GetFunctionById(params[2]);
    if (!callback) {
        pContext->ReportError("Invalid disconnect callback provided");
        return 0;
    }

    socket->set_disconnect_cb([callback, handle]() {
        extension.Defer([callback, handle]() {
            callback->PushCell(handle);
            callback->Execute(nullptr);
        });
    });

    return 0;
}

const sp_nativeinfo_t smcryptosocket_natives[] = {
    {"EncryptedSocket.EncryptedSocket", CreateEncryptedSocket},
    {"EncryptedSocket.Connect", EncryptedSocketConnect},
    {"EncryptedSocket.Send", EncryptedSocketSend},
    {"EncryptedSocket.Connected", EncryptedSocketConnected},
    {"EncryptedSocket.OnDisconnected", EncryptedSocketOnDisconnected},
    {NULL, NULL}
};