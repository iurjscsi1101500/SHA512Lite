#include <iostream>
#include "SHA512++.hpp"
using namespace SHA512;
int main() {
    const std::string input = "Hello, World!";
    unsigned char hash[64];
    sha512((const unsigned char*)input.c_str(), input.size(), hash);
    std::string hash_str = sha512_to_string(hash);
    std::cout << "Original: " << input << "\n" << "SHA-512: " << hash_str << "\n";
    return 0;
}
