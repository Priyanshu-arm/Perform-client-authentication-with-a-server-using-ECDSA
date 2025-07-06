#include<iostream>
#include<string>
#include<boost/asio.hpp>
#include"auth.pb.h"
#include"pb_encode.h"

using boost::asio::ip::tcp;
int main(){
try{
boost::asio::io_context io_context;
tcp::resolver resolver(io_context);
auto endpoints = resolver.resolve("127.0.0.1","1234");
tcp::socket socket(io_context);
boost::asio::connect(socket,endpoints);

AuthRequest msg = AuthRequest_init_zero;

strcpy(msg.serial_id, "CLIENT123456");

uint8_t signature[64] = {
    0x9f, 0xa3, 0x77, 0x21, 0x45, 0x6e, 0x3b, 0x8a,
0xd1, 0x49, 0xe2, 0xcb, 0x99, 0x01, 0xf6, 0x5d,
0x4a, 0x13, 0x3e, 0x58, 0xac, 0xfe, 0xd0, 0xb9,
0x7c, 0x81, 0x27, 0x6d, 0x3f, 0xe1, 0x18, 0xbc,
0x12, 0xaa, 0x67, 0x84, 0x5f, 0x9c, 0x23, 0x10,
0xb3, 0x76, 0xdd, 0x05, 0xe4, 0x39, 0x88, 0xc7,
0xf1, 0x6a, 0xbe, 0x91, 0x2c, 0x0f, 0xa4, 0x3a,
0x7e, 0xd5, 0x60, 0x1a, 0x59, 0x3b, 0xc8, 0x4d
};

msg.signature.size = 64;

 memcpy(msg.signature.bytes, signature, 64);

 uint8_t buffer[128];
 pb_ostream_t stream = pb_ostream_from_buffer(buffer,sizeof(buffer));

 if (!pb_encode(&stream, AuthRequest_fields, &msg)) {
    std::cerr << "Encoding failed: " << PB_GET_ERROR(&stream) << std::endl;
    return 1;
}

boost::asio::write(socket, boost::asio::buffer(buffer, stream.bytes_written));

    std::cout << "[Client] AuthRequest sent (" << stream.bytes_written << " bytes)"<<std::endl;

}
catch (std::exception &e) {
    std::cerr << "Server error: " << e.what() << "\n";
}

return 0;

}