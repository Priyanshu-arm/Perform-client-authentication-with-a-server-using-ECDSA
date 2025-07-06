#include<iostream>
#include<boost/asio.hpp>

using boost::asio::ip::tcp;

int main(){
 try{
    boost::asio::io_context io_context;
    
    tcp::resolver resolver(io_context);
    auto endpoints = resolver.resolve("127.0.0.1", "1234");

    tcp::socket socket(io_context);
    boost::asio::connect(socket, endpoints);

    std::string message = "Hello, client!";
    boost::asio::write(socket,boost::asio::buffer(message));
    
    std::cout <<"[Client] Sent:" <<message<<std::endl;



 }catch(std::exception& e){
    std::cerr <<"Error:"<<e.what()<<"\n";
 }
return 0;



}