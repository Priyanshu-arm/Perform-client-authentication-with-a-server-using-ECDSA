#include <iostream>
#include <boost/asio.hpp>
#include <cstdlib>
#include "auth.pb.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include "ecdsa.h"
#include "sha2.h"
#include "secp256k1.h"

using boost::asio::ip::tcp;

uint8_t public_key[65] = {
    0x04, 0x3a, 0x0f, 0x29, 0x59, 0x98, 0xf3, 0x13, 0x3d, 0x89, 0xb1, 0x6b, 0x87, 0x19, 0x0e, 0x2c,
    0x93, 0xb7, 0xdd, 0x43, 0xb4, 0xd6, 0xc8, 0xe2, 0x83, 0xb3, 0x4b, 0x1b, 0xf7, 0x56, 0xf2, 0x33,
    0xbd, 0xd3, 0x90, 0xbc, 0x5a, 0xd0, 0x0f, 0x4d, 0xfa, 0x80, 0x5c, 0x77, 0x4d, 0x34, 0x5e, 0x79,
    0x5e, 0xf6, 0x20, 0x6e, 0xa6, 0x85, 0xa0, 0x0c, 0x2a, 0x71, 0x95, 0xd2, 0xfd, 0x8a, 0x12, 0xe1,
    0x2c
};

int main() {
    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 1234));
        tcp::socket socket(io_context);

        std::cout << "[Server] Waiting for client on port 1234..."<<std::endl;
        acceptor.accept(socket);
        std::cout << "[Server] Client connected."<<std::endl;
uint8_t buffer[128] = {0};
        size_t length = socket.read_some(boost::asio::buffer(buffer));
        AuthRequest auth = AuthRequest_init_zero;
        pb_istream_t stream = pb_istream_from_buffer(buffer, length);
        pb_decode(&stream, AuthRequest_fields, &auth);

        uint8_t hash[32];
        sha256_Raw(reinterpret_cast<const uint8_t*>(auth.serial_id), strlen(auth.serial_id), hash);
        bool valid = ecdsa_verify(&secp256k1, public_key, hash, auth.signature.bytes);
        std::cout << "[Server] Serial ID: " << auth.serial_id << "\n"<<std::endl;
        std::cout << (valid ? "[Server] Signature OK.\n" : "[Server] Signature invalid!\n")<<std::endl;
        if (!valid) return 1;

        // Send Challenge
        uint8_t nonce[32];
        for (int i = 0; i < 32; ++i) nonce[i] = rand() % 256;
        Challenge ch = Challenge_init_zero;
        memcpy(ch.random_nonce.bytes, nonce, 32);
        ch.random_nonce.size = 32;

        uint8_t ch_buf[64];
        pb_ostream_t ch_stream = pb_ostream_from_buffer(ch_buf, sizeof(ch_buf));
        pb_encode(&ch_stream, Challenge_fields, &ch);
        boost::asio::write(socket, boost::asio::buffer(ch_buf, ch_stream.bytes_written));

        // Receive ChallengeResponse
        uint8_t cr_buf[128];
        size_t cr_len = socket.read_some(boost::asio::buffer(cr_buf));
        ChallengeResponse cr = ChallengeResponse_init_zero;
        pb_istream_t cr_stream = pb_istream_from_buffer(cr_buf, cr_len);
        pb_decode(&cr_stream, ChallengeResponse_fields, &cr);

        // Verify signed nonce
        bool nonce_ok = ecdsa_verify(&secp256k1, public_key, nonce, cr.signed_nonce.bytes);
        std::cout << (nonce_ok ? " Authenticated\n" : " Invalid nonce signature");
    } catch (std::exception &e) {
        std::cerr << "[Server] Error: " << e.what() << "\n";
    }
    return 0;
}
