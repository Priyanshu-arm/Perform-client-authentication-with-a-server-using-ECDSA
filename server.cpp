#include <iostream>

#include <boost/asio.hpp>

using boost::asio::ip::tcp;

int main(){
    try{

       boost::asio::io_context io_context; 
       tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 1234));
       std::cout << "[Server] listening on port 1234\n"<<std::endl;

       tcp::socket socket(io_context);
       acceptor.accept(socket);
       std::cout<<"[Server] client connected\n"<<std::endl;

       char data[1024] = {0};
       size_t length = socket.read_some(boost::asio::buffer(data));
       std::cout << "[Server] Received: " <<std::string(data, length) << "\n";
    



    } catch (std::exception& e){
        std::cerr <<"error: " <<e.what() <<"\n";

    }

    return 0;

}