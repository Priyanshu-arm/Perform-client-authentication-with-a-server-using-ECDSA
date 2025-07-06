#include<iostream>
#include<boost/asio.hpp>
#include "auth.pb.h"
#include "pb_decode.h"

using boost::asio::ip::tcp;

int main(){
    try{
    boost::asio::io_context io_context;
    tcp::acceptor acceptor(io_context,tcp::endpoint(tcp::v4(),1234));
    tcp::socket socket(io_context);

        std::cout << "[Server] Waiting for client connection on port 1234...\n"<<std::endl;
    acceptor.accept(socket);
    std::cout << "[Server] Client connected.\n"<<std::endl;

    uint8_t buffer[128]={0};
    size_t length = socket.read_some(boost::asio::buffer(buffer));

    AuthRequest msg = AuthRequest_init_zero;
    pb_istream_t stream = pb_istream_from_buffer(buffer,length);

    if (!pb_decode(&stream,AuthRequest_fields, &msg)){
            std::cerr << "[Server] Decoding failed: " << PB_GET_ERROR(&stream) << "\n";
    return 1;

    }

     std::cout << "[Server] Serial ID: " << msg.serial_id << "\n";
    std::cout << "[Server] Signature Size: " << msg.signature.size << " bytes\n";
} catch (std::exception &e) {
    std::cerr << "[Server] Error: " << e.what() << "\n";
}

return 0;

}