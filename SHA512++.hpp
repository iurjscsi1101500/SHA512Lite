/*
The MIT License (MIT)

Copyright (C) 2024 Atharva Tiwari

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
#pragma once
#include <iostream>
#include <vector>
#include <iomanip>
#include <sstream>
typedef unsigned long long uint64;

const uint64 K[80] = {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

const uint64 H0[8] = {
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};
namespace SHA512{
inline uint64 rotr(uint64 x, uint64 n) {
    return (x >> n) | (x << (64 - n));
}

inline uint64 shr(uint64 x, uint64 n) {
    return x >> n;
}

inline uint64 ch(uint64 x, uint64 y, uint64 z) {
    return (x & y) ^ (~x & z);
}

inline uint64 maj(uint64 x, uint64 y, uint64 z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint64 s0(uint64 x) {
    return rotr(x, 1) ^ rotr(x, 8) ^ shr(x, 7);
}

inline uint64 s1(uint64 x) {
    return rotr(x, 19) ^ rotr(x, 61) ^ shr(x, 6);
}

inline uint64 S0(uint64 x) {
    return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39);
}

inline uint64 S1(uint64 x) {
    return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41);
}

void sha512_transform(uint64 state[8], const uint64 block[16]) {
    uint64 W[80];
    for (int t = 0; t < 16; ++t) {
        W[t] = block[t];
    }
    for (int t = 16; t < 80; ++t) {
        W[t] = s1(W[t-2]) + W[t-7] + s0(W[t-15]) + W[t-16];
    }

    uint64 a = state[0];
    uint64 b = state[1];
    uint64 c = state[2];
    uint64 d = state[3];
    uint64 e = state[4];
    uint64 f = state[5];
    uint64 g = state[6];
    uint64 h = state[7];

    for (int t = 0; t < 80; ++t) {
        uint64 T1 = h + S1(e) + ch(e, f, g) + K[t] + W[t];
        uint64 T2 = S0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha512_update(uint64 state[8], const unsigned char data[], size_t len) {
    uint64 block[16];
    while (len >= 128) {
        for (int i = 0; i < 16; ++i) {
            block[i] = ((uint64)data[8*i] << 56) | ((uint64)data[8*i+1] << 48) |
                       ((uint64)data[8*i+2] << 40) | ((uint64)data[8*i+3] << 32) |
                       ((uint64)data[8*i+4] << 24) | ((uint64)data[8*i+5] << 16) |
                       ((uint64)data[8*i+6] << 8) | (uint64)data[8*i+7];
        }
        sha512_transform(state, block);
        data += 128;
        len -= 128;
    }
}

void sha512_finalize(uint64 state[8], unsigned char hash[64], const unsigned char data[], size_t len) {
    uint64 block[16] = {0};
    size_t rem = len % 128;
    for (size_t i = 0; i < rem; ++i) {
        block[i/8] |= (uint64)data[i] << (56 - 8*(i%8));
    }
    block[rem/8] |= 0x80ull << (56 - 8*(rem%8));

    if (rem >= 112) {
        sha512_transform(state, block);
        for (int i = 0; i < 16; ++i) block[i] = 0;
    }

    block[15] = len * 8;
    sha512_transform(state, block);

    for (int i = 0; i < 8; ++i) {
        hash[8*i] = state[i] >> 56;
        hash[8*i+1] = state[i] >> 48;
        hash[8*i+2] = state[i] >> 40;
        hash[8*i+3] = state[i] >> 32;
        hash[8*i+4] = state[i] >> 24;
        hash[8*i+5] = state[i] >> 16;
        hash[8*i+6] = state[i] >> 8;
        hash[8*i+7] = state[i];
    }
}

void sha512(const unsigned char *data, size_t len, unsigned char hash[64]) {
    uint64 state[8];
    for (int i = 0; i < 8; ++i) {
        state[i] = H0[i];
    }

    sha512_update(state, data, len);
    sha512_finalize(state, hash, data + len - (len % 128), len);
}

std::string sha512_to_string(const unsigned char hash[64]) {
    std::stringstream ss;
    for (int i = 0; i < 64; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}
int compare_shaTOstr(const uint8_t hash[64], std::string input) {
    uint8_t hash2[64];
    sha512(reinterpret_cast<const uint8_t*>(input.c_str()), input.size(), hash2);
    return std::equal(hash, hash + 64, hash2) ? 0 : -1;
}
}
