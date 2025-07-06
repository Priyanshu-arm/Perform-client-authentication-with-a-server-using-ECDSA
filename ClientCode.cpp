
#include <iostream>
#include <string>
#include <stdint.h>
#include <stdio.h>

#include "sha2.h"
#include "ecdsa.h"
#include "secp256k1.h"

#include "bignum.h"
#include "memzero.h"
#include "curves.h"

int main(){
const std::string serial_id="CLIENT123456";
uint8_t hash[32];
sha256_Raw(reinterpret_cast<const uint8_t*>(serial_id.c_str()), serial_id.size(), hash);

uint8_t private_key[32]= {  0x1c, 0x3d, 0x5e, 0x7a, 0x9b, 0x2d, 0x4f, 0x6a,
    0x1e, 0x3c, 0x5d, 0x7f, 0x9b, 0x2a, 0x4c, 0x6e,
    0x8d, 0x0f, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
    0xde, 0xf1, 0x23, 0x45, 0x67, 0x89, 0x0a, 0xcd};

    uint8_t signature[64];

if (ecdsa_sign(&secp256k1, private_key, hash, signature, NULL)) {
    std::cout << "[Client] Signature: ";
    for (int i = 0; i < 64; ++i)
        printf("%02x", signature[i]);
    std::cout << std::endl;
} else {
    std::cerr << "Signing failed." << std::endl;
}
return 0;

}
