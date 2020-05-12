#include "extension.hpp"
#include <boost/asio.hpp>
#include <cryptopp/secblock.h>

using boost::asio::ip::tcp;
using CryptoPP::SecByteBlock;

using namespace std;

class encrypted_socket : public enable_shared_from_this<encrypted_socket> {
public:
    encrypted_socket(string key);
    void connect(function<void()> callback, string address, uint16_t  port);
private:
    void start_read_packet();
    void do_read();
    unique_ptr<tcp::socket> socket;
    unique_ptr<boost::asio::io_service> service;
    unique_ptr<boost::asio::io_service::work> work;
    unique_ptr<boost::asio::streambuf> buffer;
    bool connected;
    size_t msg_size;
    SecByteBlock key;
};