cmake_minimum_required(VERSION 3.8)
project (hash-server)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

set(Boost_USE_STATIC_LIBS    ON)
set(Boost_USE_MULTITHREADED  ON)
set(Boost_USE_STATIC_RUNTIME OFF)
find_package(Boost COMPONENTS thread system program_options)
include_directories(${Boost_INCLUDE_DIRS})

set(GTEST_SRC /usr/src/gtest/src/gtest-all.cc)
include_directories(SYSTEM /usr/src/gtest # <-- path to non-header files from gtest-all.cc
                           /usr/include)  # <-- path to gtest headers


add_library(gtest STATIC ${GTEST_SRC})    # <-- make static library target before main project executable
target_link_libraries(gtest ${CMAKE_THREAD_LIBS_INIT})

add_executable(hash-server-tests main.cpp)
target_compile_definitions(hash-server-tests PUBLIC HASH_SERVER_TESTS)
target_link_libraries(hash-server-tests ${Boost_LIBRARIES} /usr/lib/libcrypto++.a gtest)

add_executable(hash-server main.cpp)
target_link_libraries(hash-server ${Boost_LIBRARIES} /usr/lib/libcrypto++.a)
