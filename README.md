# hash-server
A concurrent implementation of the service which returns SHA256 hashes for every line arrived via TCP (line ends with \n)

## Implementation Details

The application is implemented and tested on Ubuntu 16.04

C++11 standard is used to make build and deployment easier on required version of Ubuntu (that is Ubuntu 16)

The following libraries/frameworks are used

Google Test 1.7.0

Boost.Asio 1.58

Crypto++ 5.6.1

IMPORTANT: All the specified above libraries are linked statically. So there will be no problems with deployment on minimal Ubuntu (just gcc runtime is required). The dependencies are listed bellow:
```
$ ldd hash-server
        linux-vdso.so.1 =>  (0x00007ffc2247a000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fcf5f8b5000)
        libstdc++.so.6 => /usr/lib/x86_64-linux-gnu/libstdc++.so.6 (0x00007fcf5f533000)
        libm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x00007fcf5f22a000)
        libgcc_s.so.1 => /lib/x86_64-linux-gnu/libgcc_s.so.1 (0x00007fcf5f014000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fcf5ec4a000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fcf5fad2000)
```
A thread-pool is used with number of working threads equals to boost::thread::hardware_concurrency()

The build system is: CMake 3.13.4

The description of the program internals is written using Doxidgen 1.8.11

The implementation is based on the following Boost library example:
https://www.boost.org/doc/libs/1_58_0/doc/html/boost_asio/example/cpp11/echo/async_tcp_echo_server.cpp

## Before you build you need to do the following steps

```bash
sudo apt-get install make
sudo apt install gcc
sudo apt install libboost-all-dev
sudo apt install libcrypto++-dev
 
wget https://github.com/Kitware/CMake/releases/download/v3.13.4/cmake-3.13.4.tar.gz
tar -zxvf cmake-3.13.4.tar.gz
cd cmake-3.13.4
./bootstrap
make
sudo make install
sudo ln -s /usr/local/bin/cmake /usr/bin/cmake
```  

## To build release configuration

You need to be in project root dir (hash-server) 
In order to build release configuration do the following:
```bash
mkdir --parents ../hash-server-release
cd ../hash-server-release
cmake -DCMAKE_BUILD_TYPE=Release ../hash-server
cmake --build .
```
