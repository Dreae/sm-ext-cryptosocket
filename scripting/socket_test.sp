#include <sourcemod>
#include "include/cryptosocket"

public Plugin myinfo = {
    name = "SocketTest",
    author = "Dreae <dreae@dreae.onl>",
    description = "Test plugin please ignore",
    version = CRYPTOSOCKET_VERSION,
    url = "https://gitlab.com/Dreae/sm-ext-cryptosocket"
}

EncryptedSocket socket = null;

public void OnPluginStart() {
    RegServerCmd("cryptosocket_test", socket_test);
    RegServerCmd("cryptosocket_connect", socket_connect);
}

public Action socket_test(int args) {
    char argString[256];
    GetCmdArgString(argString, sizeof(argString));
    socket.Send(argString, strlen(argString));

    return Plugin_Handled;
}

public Action socket_connect(int args) {
    if (socket != INVALID_HANDLE) {
        socket.Close();
    }

    char argString[256];
    GetCmdArgString(argString, sizeof(argString));
    
    socket = new EncryptedSocket("key_id", "testkey", data_callback);
    socket.Connect(argString, 4147);

    return Plugin_Handled;
}

public void data_callback(const char[] data, int data_size) {
    PrintToServer("Got data %s", data);
}