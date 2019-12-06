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

# first we can indicate the documentation build as an option and set it to ON by default
option(BUILD_DOC "Build documentation" ON)

# check if Doxygen is installed
find_package(Doxygen)
if (DOXYGEN_FOUND)
    # set input and output files
    set(DOXYGEN_IN ${CMAKE_CURRENT_SOURCE_DIR}/../docs/Doxyfile.in)
    set(DOXYGEN_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

    # request to configure the file
    configure_file(${DOXYGEN_IN} ${DOXYGEN_OUT} @ONLY)
    message("Doxygen build started")

    # note the option ALL which allows to build the docs together with the application
    add_custom_target( doc_doxygen ALL
        COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYGEN_OUT}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        COMMENT "Generating API documentation with Doxygen"
        VERBATIM )
else (DOXYGEN_FOUND)
  message("Doxygen need to be installed to generate the doxygen documentation")
endif (DOXYGEN_FOUND)