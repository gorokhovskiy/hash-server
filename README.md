# hash-server
Concurrent implementation of a service which returns SHA256 hashes for every line arrived via TCP (line ends with \n)

## Implementation Detales

The application is implemented and tested on Ubuntu 16.04

The following libraries/frameworks are used

Google Test 1.7.0

Boost.Asio 1.58

Crypto++ 5.6.1


A thread-pool is used with number of working threads equals to boost::thread::hardware_concurrency()

The build system is: CMake 3.13.4

The description of the program internals is written using Doxidgen
