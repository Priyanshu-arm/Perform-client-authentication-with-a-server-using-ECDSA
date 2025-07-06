#include <iostream>
#include <boost/asio.hpp>
#include "auth.pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "ecdsa.h"
#include "secp256k1.h"

using boost::asio::ip::tcp;

uint8_t private_key[32] = {
 0x1c, 0x3d, 0x5e, 0x7a, 0x9b, 0x2d, 0x4f, 0x6a,
    0x1e, 0x3c, 0x5d, 0x7f, 0x9b, 0x2a, 0x4c, 0x6e,
    0x8d, 0x0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
    0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xcd

};

int main(){
 try{
   boost::asio::io_context io_context;
   tcp::resolver resolver(io_context);
   auto endpoints = resolver.resolve("127.0.0.1","1234");
   tcp::socket socket(io_context);
   boost::asio::connect(socket, endpoints);


uint8_t ch_buf[64];
size_t ch_len = socket.read_some(boost::asio::buffer(ch_buf));

Challenge challenge = Challenge_init_zero;
pb_istream_t ch_stream = pb_istream_from_buffer(ch_buf, ch_len);
pb_decode(&ch_stream, Challenge_fields, &challenge);

uint8_t signed_nonce[64];
        ecdsa_sign(&secp256k1, private_key, challenge.random_nonce.bytes, signed_nonce, NULL);

ChallengeResponse response = ChallengeResponse_init_zero;
response.signed_nonce.size = 64;
memcpy(response.signed_nonce.bytes, signed_nonce, 64);

uint8_t resp_buf[128];
pb_ostream_t resp_stream = pb_ostream_from_buffer(resp_buf , sizeof(resp_buf));
pb_encode(&resp_stream, ChallengeResponse_fields, &response);

boost::asio::write(socket, boost::asio::buffer(resp_buf, resp_stream.bytes_written));
        std::cout << "[Client] ChallengeResponse sent"<<std::endl;




 }
catch (std::exception& e) {
        std::cerr << "[Client Error] " << e.what() << "\n";
    }
    return 0;
}







}