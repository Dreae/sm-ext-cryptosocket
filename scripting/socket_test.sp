#include <sourcemod>
#include <cryptosocket>

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
    socket = new EncryptedSocket("key_id", "testkey", data_callback);
    socket.Connect("127.0.0.1", "4147");
}

public Action socket_test(int args) {
    char argString[256];
    GetCmdArgString(argString, sizeof(argString));
    socket.Send(argString, strlen(argString));

    return Plugin_Handled;
}