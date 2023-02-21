cmake_minimum_required(VERSION 3.17)
project(dianadel)

set(CMAKE_CXX_STANDARD 14)

include_directories(. /usr/local/opt/openssl/include)
link_directories(/usr/local/opt/openssl/lib)

link_libraries(-lcrypto -lssl)

add_executable(dianadel
        constrained_prf.cpp
        constrained_prf.h
        diana.cpp
        diana.h
        dianadel.cpp
        dianadel.h
        main.cpp
        sse_benchmark.cpp
        sse_benchmark.h)
