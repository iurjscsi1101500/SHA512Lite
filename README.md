# SHA512Lite - a SHA512 hash generator
A light-weight SHA512 hash generator made in C++ </br >
Copyright &copy; 2024 Atharva

## Introduction
SHA512Lite is a light-weight SHA512 hash-genarator made in C++

- Header file
- no extra dependencies (except C++11 STDLIB)
- Licenesed under MIT License
- A function to compare a string to a hash

## Generating SHA512 hash from std::string
```c++
std::string test = "Hello, World!";
unsigned char hash[64];
SHA512::sha512((const unsigned char*)test.c_str(), test.size(),hash);
std::cout << "SHA512: " << reinterpret_cast<const std::string>sha512_to_string(hash) << "\n";
```
