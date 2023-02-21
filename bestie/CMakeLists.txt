# cmake_minimum_required(VERSION <specify CMake version here>)
project(bestie)

set(CMAKE_CXX_STANDARD 11)

include_directories(. /usr/local/opt/openssl@1.1/include)
link_directories(/usr/local/opt/openssl@1.1/lib)
add_definitions("-g")
link_libraries(-lcrypto -lpthread)

add_executable(bestie
        main.cpp
        bestie.cpp
        bestie.h
        sse_benchmark.cpp
        sse_benchmark.h)
